# forms.py
from django import forms
from .models import DuosChallenge, DuosMatch, DuosMatchResult, DuosDisputeProof, DuosDirectChallenge, DuosMatchSupport, SupportCategory
from django.utils import timezone
from users.models import Profile
from django.core.exceptions import ValidationError
import pytz
from django.utils.timezone import is_aware, make_aware, utc


class DuosChallengeForm(forms.ModelForm):
    search_only = forms.BooleanField(label='Search Only', required=False)
    controller_only = forms.BooleanField(label='Controller Only', required=False)
    challenge_players = forms.ModelMultipleChoiceField(queryset=None, required=True, widget=forms.CheckboxSelectMultiple)

    class Meta:
        model = DuosChallenge
        fields = ['scheduled_date', 'search_only', 'controller_only', 'challenge_players']

    def __init__(self, *args, **kwargs):
        team = kwargs.pop('team', None)
        super().__init__(*args, **kwargs)
        if team:
            players_queryset = team.players.filter(eligible=True)
            self.fields['challenge_players'].queryset = players_queryset

    def clean(self):
        cleaned_data = super().clean()
        selected_players = cleaned_data.get('challenge_players')
        
        # Check if exactly 2 players are selected
        if selected_players.count() != 2:
            raise ValidationError("Please select exactly 2 players.")

        return cleaned_data

    def clean_scheduled_date(self):
        scheduled_date = self.cleaned_data.get('scheduled_date')
        if scheduled_date:
            # self.user.timezone is already a timezone object because of TimeZoneField
            user_timezone = self.user.timezone

            # Make sure scheduled_date is timezone-aware in the user's timezone
            if not scheduled_date.tzinfo:
                raise forms.ValidationError('The scheduled date must be timezone-aware.')

            current_time_user_timezone = timezone.now().astimezone(user_timezone)
            print(current_time_user_timezone)

            if (scheduled_date - current_time_user_timezone).total_seconds() < 1200:
                raise forms.ValidationError("Scheduled date must be at least 20 minutes in the future.")
            
            # Convert to UTC for storage and consistency
            scheduled_date_utc = scheduled_date.astimezone(pytz.utc)
            return scheduled_date_utc


class DuosDirectChallengeForm(forms.ModelForm):
    search_only = forms.BooleanField(label='Search Only', required=False)
    controller_only = forms.BooleanField(label='Controller Only', required=False)
    challenge_players = forms.ModelMultipleChoiceField(queryset=None, required=True, widget=forms.CheckboxSelectMultiple)

    class Meta:
        model = DuosDirectChallenge
        fields = ['scheduled_date', 'search_only', 'controller_only', 'challenge_players']

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        if user:
            current_team = user.current_duos_team
            if current_team:
                players_queryset = current_team.players.all()
                self.fields['challenge_players'].queryset = players_queryset
                

    def clean(self):
        cleaned_data = super().clean()
        selected_players = cleaned_data.get('challenge_players')
        
        # Check if exactly 2 players are selected
        if selected_players.count() != 2:
            raise ValidationError("Please select exactly 2 players.")

        return cleaned_data

    def clean_scheduled_date(self):
        scheduled_date = self.cleaned_data.get('scheduled_date')
        
        if scheduled_date:
            user_timezone = self.user.timezone
            utc_offset = user_timezone.utcoffset(scheduled_date).total_seconds()
            utc_scheduled_date = scheduled_date - timezone.timedelta(seconds=utc_offset)
            return utc_scheduled_date

class DuosMatchResultForm(forms.ModelForm):
    team_result = forms.ChoiceField(
        choices=[('win', 'Win'), ('loss', 'Loss')],
        widget=forms.RadioSelect,
        required=True
    )

    class Meta:
        model = DuosMatchResult
        fields = ['team_result']

class DuosDisputeProofForm(forms.ModelForm):
    class Meta:
        model = DuosDisputeProof
        fields = ['game1_screenshot', 'game2_screenshot', 'game3_screenshot', 'claim', 'additional_evidence']
        widgets = {
            'claim': forms.Textarea(attrs={'class': 'form-control', 'rows': 5}),
            'additional_evidence': forms.Textarea(attrs={'class': 'form-control', 'rows': 5}),
        }

class DuosMatchSupportForm(forms.ModelForm):
    class Meta:
        model = DuosMatchSupport
        fields = ['category', 'description', 'additional_evidence']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['category'].queryset = SupportCategory.objects.all()



class DuosPlayerSelectionForm(forms.Form):
    challenge_players = forms.ModelMultipleChoiceField(
        queryset=Profile.objects.none(),
        widget=forms.CheckboxSelectMultiple,
        required=True
    )

    def __init__(self, *args, **kwargs):
        team_players = kwargs.pop('team_players', None)
        super().__init__(*args, **kwargs)
        if team_players:
            self.fields['challenge_players'].queryset = team_players.filter(eligible=True)

    def clean_challenge_players(self):
        selected_players = self.cleaned_data.get('challenge_players')
        if len(selected_players) != 2:
            raise ValidationError("Please select exactly 2 players.")
        return selected_players