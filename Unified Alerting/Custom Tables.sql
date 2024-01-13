SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

CREATE TABLE [Custom].[SNow_Close_Queue](
    [EventID] [int] NULL,
    [ActionID] [int] NULL
) ON [PRIMARY]
GO


CREATE TABLE [Custom].[SNow_Last_Closed_Time](
    [LastClearedEndTime] [datetime] NULL
) ON [PRIMARY]
GO