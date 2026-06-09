package main

import (
	"go.temporal.io/sdk/activity"

	"github.com/vinodhalaharvi/gitlab-sentinel/jira"
	"github.com/vinodhalaharvi/gitlab-sentinel/scanners/dormancy"
	"github.com/vinodhalaharvi/gitlab-sentinel/scanners/oauth"
	"github.com/vinodhalaharvi/gitlab-sentinel/scanners/regex"
	"github.com/vinodhalaharvi/gitlab-sentinel/scanners/scopes"
)

// Activity name strings live in their owning packages as ActivityName
// constants. The registration helpers below tie those names to the
// concrete function values for the worker.

func regexActivityOptions() activity.RegisterOptions {
	return activity.RegisterOptions{Name: regex.ActivityName}
}

func oauthActivityOptions() activity.RegisterOptions {
	return activity.RegisterOptions{Name: oauth.ActivityName}
}

func scopesActivityOptions() activity.RegisterOptions {
	return activity.RegisterOptions{Name: scopes.ActivityName}
}

func dormancyActivityOptions() activity.RegisterOptions {
	return activity.RegisterOptions{Name: dormancy.ActivityName}
}

func jiraActivityOptions() activity.RegisterOptions {
	return activity.RegisterOptions{Name: jira.ActivityName}
}
