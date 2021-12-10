Return-Path: <kasan-dev+bncBCU73AEHRQBBBQGIZ6GQMGQEPEJ54PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7405B470EC6
	for <lists+kasan-dev@lfdr.de>; Sat, 11 Dec 2021 00:35:29 +0100 (CET)
Received: by mail-ua1-x93a.google.com with SMTP id g9-20020ab04e09000000b002e8ebb5df39sf7323014uah.16
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Dec 2021 15:35:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639179328; cv=pass;
        d=google.com; s=arc-20160816;
        b=dmJ1hfX+m7r17hYeOxNoXWL2H31CPQrBjb0RRuJrmkzxEINUCVky/kv9f75cqYyOtX
         AXrE+KS8iFRJsZ++zqUP4tn7zFg5/jpS0u/+eyAnglHIJ1rVko0qq11kFOI7GJsheAKV
         5Un2JnExohKWvBNHsLg/tV5YXmgS9BDzplt1Fs3V3PA/5Q3B+o1sdaETF90DCw+xuenJ
         HQJlZWqlSTjsTmDpDkQ+PGqGpQiwfvsbiDHhryMz+MOBAIuvqWBA7YSYDO8VmKCb7CPs
         XCQO9VB6i1HOC90jLMPdNuEn15HetVgNqvLwzAe79675AIIVt7SVX+dyuuw8dMW1DL1d
         a21Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=pO8M1fmtD8N9oUuNRGHWASD5gKx06NHzxI5Is9eei6Q=;
        b=pNmd+WwrdGdKqRiW3DH37TcYSoqWoJbc/v564ngctjp5px/BQLMc3SfXUhlg7KTPne
         P4VsCZobOBNL+6Nseca2bRcdAaMw9wUqQF8plN9yPxKCD2dHGknXAvXc6TVIiAPfSWX0
         mZAWK4KcDAIo3yn3aR5lib+REyV4qQEr50gWTJgWQvLVhh95F8/5eDbiwwquxBr6l7vo
         +ixEh1CnUZWqvD2VM+HmpGl5HUmE4uZy1iPl+VXmAqIkjurZTPEzFjZvZdaLmKsTOkXI
         BD6wmRrb8lIREmHgkBD03hiRaMlcAfCRqhj9Am6sJ83VjqaUelrEzIzhX6ddPkUjk9G9
         tqsg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=29pc=q3=goodmis.org=rostedt@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=29pc=Q3=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pO8M1fmtD8N9oUuNRGHWASD5gKx06NHzxI5Is9eei6Q=;
        b=SU3lwkUOKu/CvS8+No9LxWIx9H0HrWGV3kTZlBw+yZcm6f9M6Loue1Vr7vYSJTlKug
         cyQ8G/oC3J9PMKjspgxwhjTRlvrECGKc+YJRe4U0FDeazEsRCpIQFlU5+DeXP5/V0J2F
         k8gwUlRG8nkOMp2IK+s9GGetHZNm2ANvPB0vOP9RxIQeCnRg8b5PIoloiydlWhQl3lKp
         6FFwFdjRaV4u3EFCVOMqlR3/LbMQuOUdVV0lSr1aLsrYoo2k5Dov8LlC8RNMGZ/MsO+q
         6x0tL8iNIXwMylWhF/WamBTjfYLx91GRm241eSXcJc4Jxkewmm8+r1mQdQgLpdAolCHU
         u+3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pO8M1fmtD8N9oUuNRGHWASD5gKx06NHzxI5Is9eei6Q=;
        b=c70oJ6PyHvjhDKcLM+AWk4WKmQ9ZwzABHYMp4AjNqy+lVe3ePl4CKYFe5ePvW9jagI
         g2JY0JQtt06c/HrX72Ol6pLn9ADZyO3AOgHi1W60Vetsj9iCKP8ijK5FQXSkxWvcsJ6j
         1nS9YR49+pR9l09FxOAhJYCyVCJphpHAiZHw8nLkeb8dMt0/tHiGm2+uTd1rPflMPOJQ
         PldPtPHDWShf7Rk6Hgsd/2pdNl/8O82oNDB0ZGro1eosVw8sbFcozt6mlK8J1c1cfMKh
         tWwqlsnNAZ+U1TZT32B5bWoQVmoWCYPfcMwxoO1Gf6Wl9py+g40iLFHDMU7zTuNcoord
         7QVQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533MMDmCHveP1uJ/tlgnFNAQ1G1I2eVs/ZiLhfyTTuPpuaLuzdcq
	X3F5KSiJNYoUHvgsKaNVqj0=
X-Google-Smtp-Source: ABdhPJwZTPzYr1lX3EQRE2QTMJHk6/FjpXubAvZJWNwjpNQc+ekNGQj9bfY8K9GLQ8hwgsucVKMigg==
X-Received: by 2002:a05:6122:104f:: with SMTP id z15mr23617421vkn.39.1639179328523;
        Fri, 10 Dec 2021 15:35:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:43cd:: with SMTP id q196ls1984005vka.2.gmail; Fri, 10
 Dec 2021 15:35:28 -0800 (PST)
X-Received: by 2002:a05:6122:d09:: with SMTP id az9mr23522249vkb.23.1639179327965;
        Fri, 10 Dec 2021 15:35:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639179327; cv=none;
        d=google.com; s=arc-20160816;
        b=N8J7AmxZ5eiiBu56f9fz9qXgnyDqMDFu7IH9voKPVGXrgHFqqpWFOWVnvvt05mjjD7
         EDennPAmfcriJj9UD8xHBrnxwZzq8CLI8OkhWcckWn0N7diCK35IvN4VLC66WvzlHxjv
         oFNMrhPtBYixZo4InYXwh65FsyIbogbJpBQecwZo0pSkea7s9VAF0eCKewoU/hMd8WWm
         1IzA8bPl68tRHCrYjFf4IMZCgyJ27SyyiebMn7Y4+0D8BPtePzLA997Z5qxjIQyaAHxm
         r37Twh+pwL8oGBlEz8VZXJrCi1v62aSMzYYJqRBOekjaXCoPM/p2tzUgPjZVwsWWU/P6
         DX3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=FeT7JMT3rl3kGRNCbFV0bvk4lsvEjAYka7g6OsyEHpA=;
        b=j/Nj+jWdurVFi3uly00R0srFDNjnS/yQ6Ud4pXCBtvPobAMCjtnaC/YgKeGMQn3DPJ
         71RBdWqICnDtPwgNnneSDfDHouN7vVyhubyStj9BlcBKBaCb4DOw6JhTThkYeL5WVVyC
         MFohiVTF2FZsy+l6fU1P2MvRFa+qNIVJsRI72GACCyNU5dLPyEEnaFPNQpJdgxQty28M
         KwhqIIq7mnS1hjUghARo7ym1Cu77OQaNUpK6MeoYzT2nMfdfGsj40Gdwb1JkE2eq6DFf
         hTndaL8IkeIIvNozfwqgOxB2OHK8m3IMvllYh4XNTtGdSf4s3XG3CazHuvRuzbMULzEq
         sVTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=29pc=q3=goodmis.org=rostedt@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=29pc=Q3=goodmis.org=rostedt@kernel.org"
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id v5si453615vsm.1.2021.12.10.15.35.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 10 Dec 2021 15:35:27 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=29pc=q3=goodmis.org=rostedt@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by sin.source.kernel.org (Postfix) with ESMTPS id 31D55CE2D87;
	Fri, 10 Dec 2021 23:35:25 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D8B52C00446;
	Fri, 10 Dec 2021 23:35:21 +0000 (UTC)
Date: Fri, 10 Dec 2021 18:35:20 -0500
From: Steven Rostedt <rostedt@goodmis.org>
To: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
Cc: Marco Elver <elver@google.com>, Ingo Molnar <mingo@redhat.com>,
 Alexander Potapenko <glider@google.com>, Andrew Morton
 <akpm@linux-foundation.org>, Petr Mladek <pmladek@suse.com>, Luis
 Chamberlain <mcgrof@kernel.org>, Wei Liu <wei.liu@kernel.org>, Mike
 Rapoport <rppt@kernel.org>, Arnd Bergmann <arnd@arndb.de>, John Ogness
 <john.ogness@linutronix.de>, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Alexander Popov <alex.popov@linux.com>
Subject: Re: [PATCH] panic: use error_report_end tracepoint on warnings
Message-ID: <20211210183520.5cb1c4d4@gandalf.local.home>
In-Reply-To: <YZJ01V8fZBlWz4VW@smile.fi.intel.com>
References: <20211115085630.1756817-1-elver@google.com>
	<YZJw69RdPES7gHBM@smile.fi.intel.com>
	<CANpmjNMcxQ1YrvsbO-+=5vmW6rwhChjgB20FUMKvHQ9HXNwcAg@mail.gmail.com>
	<YZJ01V8fZBlWz4VW@smile.fi.intel.com>
X-Mailer: Claws Mail 3.17.8 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=29pc=q3=goodmis.org=rostedt@kernel.org designates
 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=29pc=Q3=goodmis.org=rostedt@kernel.org"
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

On Mon, 15 Nov 2021 16:55:17 +0200
Andy Shevchenko <andriy.shevchenko@linux.intel.com> wrote:

> > > >       ERROR_DETECTOR_KFENCE,
> > > > -     ERROR_DETECTOR_KASAN
> > > > +     ERROR_DETECTOR_KASAN,
> > > > +     ERROR_DETECTOR_WARN  
> > >
> > > ...which exactly shows my point (given many times somewhere else) why comma
> > > is good to have when we are not sure the item is a terminator one in the enum
> > > or array of elements.  
> > 
> > So you want me to add a comma?  
> 
> Yes. And you see exactly why I'm asking for that.
> 
> > (I'm not participating in bikeshedding here, just tell me what to do.)  
> 
> Done!

Is there going to be another patch set? Or did I miss it?

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211210183520.5cb1c4d4%40gandalf.local.home.
