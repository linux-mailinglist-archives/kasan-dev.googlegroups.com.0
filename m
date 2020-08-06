Return-Path: <kasan-dev+bncBC24VNFHTMIBBBMKWD4QKGQETNQALWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3b.google.com (mail-vs1-xe3b.google.com [IPv6:2607:f8b0:4864:20::e3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 779AF23DAB3
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Aug 2020 15:26:30 +0200 (CEST)
Received: by mail-vs1-xe3b.google.com with SMTP id z8sf10388775vsj.15
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Aug 2020 06:26:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596720389; cv=pass;
        d=google.com; s=arc-20160816;
        b=XtAvoEycLTwd4Sx5mM7Gkoe3tcdB/yLftVHUoQv6Cz1dAr6sJvFdiJFVIy4GdVXPnK
         TCCC3q6vVpnt/eM9TCwNItvA082g704fCMrWyoKvCsvQJs73CX+dri6pldaIsqGDOnmg
         62tIMK3JFFcoYr3fAyqhi3c+War2uwaHRilxU/6kB2zIR1HKMFlFsHFKR0n+VA4fJTkO
         GlQSb3Y1gGtE3ao1aS5g5BPmBQsxnJU6kWrNJbomAFe3SCfvcGIfbsx48pS2nrlRBQSC
         Y3Vu4Ec6un8uCivdezVIOgsp5tfvFwwmK/qt+lSi6gSuAL5Ii5z/4VNbCyYo/94Q9+S6
         eS2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=0fh3MgoK5u8c2skcncW/s6iFmqhbhwXWL4HDJn2yHag=;
        b=YCBGGUebooNULdyi3VskKTLUVIrssQ6D21N3evjYQT2gaqOBh8ZTlGQcrPcemBzMCR
         nPEkJZwjC3FmsEIlvtA7hHQnPytZlEEKFZ+jFcXTd3w0LABYm2B3ohuz7cbrSBMtf8YF
         gpOdA6o0Mnczftwetw/fp+9Wt+NX7ccaC74cuu+cfoVt4e9xHBOVTew6NcDZo1zR8jcB
         98MPxqeVaCX8E0fO90W8XwQsEkagnl5eEq9IgJ+c9LmFEDqROmoGsR9l4p7TR/wWJC/M
         +Zhxe/ODPNBjpiBLY1lL5TYFRB/uQcO2bPJQ6IKKcQQ5ey0R4/OCoE8YWAOlJgugbrlG
         +2bA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=ac95=bq=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=AC95=BQ=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0fh3MgoK5u8c2skcncW/s6iFmqhbhwXWL4HDJn2yHag=;
        b=DkuQJh+PSV0DfvU6G6tXyTR+mZvch4DyFxfTqYhFzQvvUeBoe7KCvHMVXymaEdzIec
         tmXd+8C1cNqxpacLEM+v5sEOaw4kd612MCrnbiYBlkwMgUW/tgRxB2R7R+DJtmRhDraQ
         Rqv/3VvM+mHWU7ECo1Cq0omji0S1IWd3nxFWcXmxfGwMPHWTE4LGL0o7reGdRDfA0CuA
         jzCSLXvDhIaPtDa5od2rCxqSU8qHUdbEdNM5H4DF+2uIDLPs0v4PIw3N4KmNvTAxMP0z
         CfyheglEKTS7z4VoRhQVddYsUVWn4+TvYkauaPG6g5CLYJT8EWbkrKmDynyo34gbunkP
         kcWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=0fh3MgoK5u8c2skcncW/s6iFmqhbhwXWL4HDJn2yHag=;
        b=sQZZHiy9SkrB26vqQRELyRHSPrscDIHw2zKKobcf1iRd2iyVY5vjpZxOXmMM36KvB6
         CNC8Xi2dIUjtyZvP1LT6YR7NG6kOYy/QT+w8cilRnvs+eRoIgDIrnSWdQKq9k7kZSBKm
         My1OAhZ8glMHdO5sQt1iBsxnxwrRLGIRBIilmdgzt2n6k0tNGdePmGHuhCaNFo3/aFK3
         Vezi1isfYof617AQXbHatY82L3MilCs8kz4BschLFWWiqwfes1Akc4mUJDr6vhtYiJBy
         l7VTkj/+WFmrtb9j/fmMLUgFPl8iKxXdYNqWZnXllnTC1SgfjOnQYW/5rrjKlScQA760
         +jYA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530tT8WNpURSq97CQTOGTp1qEL2dtjkmJrAViroanrfk6k0hF435
	hVq3XrSSaj3k4r6LPBtnPBg=
X-Google-Smtp-Source: ABdhPJzXzLU+qN05ScJ+PHwM0zOmXsI2adUzcwNsdXzUhbQ5RixBKx67Gx8Xa8p1jtZranUMqeETTA==
X-Received: by 2002:a67:1bc7:: with SMTP id b190mr6030789vsb.211.1596720389552;
        Thu, 06 Aug 2020 06:26:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f415:: with SMTP id p21ls505531vsn.7.gmail; Thu, 06 Aug
 2020 06:26:29 -0700 (PDT)
X-Received: by 2002:a67:7d50:: with SMTP id y77mr6449385vsc.207.1596720389103;
        Thu, 06 Aug 2020 06:26:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596720389; cv=none;
        d=google.com; s=arc-20160816;
        b=QCX3N4puxFcuv7WsQcvUDlgyrd63XJ4G+i1AIIs56JKwnQvdYPptD40UVZNBeMQ2GO
         JjpKfZ+hr8zCNY/n5DtgfEpyriKW9Sssb2AuxRTxnV1SEAjoyrKC3u33Gxit/szPCxJu
         aFUM/QZpopVa8N6GRPBpG2q3SvV6czXmTduuZdsWnzGPqt3cm3VMhOhXWNERd9s/Z1Lh
         dRoPX+EUs7lRNYwk0JELYqb7shdMysTqp7SD9eczPfK1QiolzIgb/Pl6On9gpnvgUogb
         ecnPOpUSFO0CxPHygrfuxSWZhgmvyE7afIqTbyqYKkwe7utADZ+yxbJQEcQL+hRgHUI3
         nr/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=TK/sTQoHqZsdRnhJ/LNhO7dkXOV6DXZIc6EfxFwUv4M=;
        b=geoqEb6DT9dsA7OYdRGMyDtHJxtPE9fy2rHnCjyuseJFMULShDtopg6cSbrmyuDOSX
         XylO8TvNYpQK7ePQWeHjmIL1vqjAO72iN7C2b3fRSebD4wWLUewCMZArRLS1d1RO3iDT
         6OW+5ZdaB/enxu7usuXL3sYyurAyrTmwev91xGhH3Y9qGk63bXVzwEhiuz7kwoCmx9f2
         dHxA+ETKefJep+XisIiUPHjNGBFluBH5aoZ5EXvRLY9SD3lEkRER37s2k5cKKuIF/l2S
         LB+SNGZonb8g5lokn2FAFB5bBz2yMcoQbL9AKQzzO590WaUI/WWpu02uNmZ+aDGBw5BJ
         yA1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=ac95=bq=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=AC95=BQ=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id j18si279033vki.3.2020.08.06.06.26.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 06 Aug 2020 06:26:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=ac95=bq=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 208299] Add fuzzing-optimized RCU mode that invokes RCU
 callbacks ASAP
Date: Thu, 06 Aug 2020 13:26:27 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-208299-199747-c3n5PqFbBL@https.bugzilla.kernel.org/>
In-Reply-To: <bug-208299-199747@https.bugzilla.kernel.org/>
References: <bug-208299-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=ac95=bq=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=AC95=BQ=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

https://bugzilla.kernel.org/show_bug.cgi?id=208299

Dmitry Vyukov (dvyukov@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |dvyukov@google.com

--- Comment #1 from Dmitry Vyukov (dvyukov@google.com) ---
This now exists as rcupdate.rcu_expedited=1 and was enabled on syzbot:
https://github.com/google/syzkaller/pull/2021

...which was added in 2012...
https://github.com/torvalds/linux/commit/3705b88db0d7cc4
Paul?

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-208299-199747-c3n5PqFbBL%40https.bugzilla.kernel.org/.
