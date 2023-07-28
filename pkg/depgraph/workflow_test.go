package depgraph

import (
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
)

func Test_Depgraph_Init(t *testing.T) {
	config := configuration.New()
	engine := workflow.NewWorkFlowEngine(config)

	err := Init(engine)
	assert.Nil(t, err)

	allProjects := config.Get("all-projects")
	assert.Equal(t, false, allProjects)

	inputFile := config.Get("file")
	assert.Equal(t, "", inputFile)
}
