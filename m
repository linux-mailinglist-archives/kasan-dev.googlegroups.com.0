Return-Path: <kasan-dev+bncBCU73AEHRQBBBNPCV6XAMGQEVQAGHUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id B05E0853F02
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 23:46:15 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id 41be03b00d2f7-5ce12b4c1c9sf4103683a12.1
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 14:46:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707864374; cv=pass;
        d=google.com; s=arc-20160816;
        b=NPsjmPL+1QVlLl1c8j2wSUMvonJlIXB7vMqdjD5qq1ctG0ifr3O84ZRMD1TgaBkG+r
         0pbNbJvfrfHFbyXRXQa0IRDYHzrF7DEspgCr+HZhJQWkwAfwck8NfFKPIiuouVjWrCft
         tyIWK/bEm7wmkFjRU3CQ1qQS6j/7XvnrX+rtr5hp7A77O0nMDoxiu9ASgI4cggHzpPs3
         rXDwFZQj4OETU5jQ1WH+fnl/cwitdFsiB0CeN+2c159XFQe4L02dvA7x+WeVcsioxZwC
         c/X/yjgiBKy/4PJdU0xN/+5P1QGjyu44o9ugL6znC9L51zacOb9Ank8OGfTTEuAZxVAb
         lbEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=iE71XjO7GGoBPryJVEEuk8fAHARCQLvs9QAoEVJFYXo=;
        fh=QbHqEUtvlXBMx9Iuti8XCuA/pi1ASK/3k47LkTosSAg=;
        b=bSemuJZbjfvQw3uiB5x6EM+2ulHHnirSMOxtzJNsRXbaoV+RlqivF0f/C7ytojhuRV
         hexVacrVJE5Pzu8MTUiaY1eiTWyvaaSKUsS6R5DFzlrb32p+RMbCdXWv+2L8OKhrtPwz
         gj57+GH4QqcKfiDjTNsIEfnETvDJCpVCvDov3paeajUbhkKvz/lBV4svQseHs308Eemt
         tLMJoWnH805phQZzeStqiADHdgiaVvJ+Md+4OQtQnSTBqFizb6Ra4iBP1A4GhhDJZpTF
         dBkRaFOd1glrHg07D4ozaWVJLTmGphir5pXTX7iGFRFrX/xcQRYP2MEqWdw33Ut+6Jy0
         AeHA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=4rjb=jw=goodmis.org=rostedt@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=4RJB=JW=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707864374; x=1708469174; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=iE71XjO7GGoBPryJVEEuk8fAHARCQLvs9QAoEVJFYXo=;
        b=SwI70Z5w5gC9oaV2vIa48J22HTujeLZF0gzobDnpPx5jqSUh8zy+6R1b/FNF2fBCDN
         DKYA8hR0+98ewcz1X9lMFkRqzWnn/YbDgZzUIBVpf8HTyEqz2RRUThQoxrxr7cqF8w4L
         lp3//w5ZvDDt8FRbVkke7O4oRAsUpbickapVd+7LczKfAcCo6hIBJHcZKcxiB1JUwCUL
         ISiJs5vvSlj/jtyDuubt/fw+R9T6jbePug6s+PVUVD/VIDSf4HbRiEFPlM4khywM2BzL
         d3t26ys0jVvEIdL8Ude83GuCqosQVgOL87ERdwddnEgVOJmVotYNY8ztHE+rGmfwFtUh
         HCzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707864374; x=1708469174;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=iE71XjO7GGoBPryJVEEuk8fAHARCQLvs9QAoEVJFYXo=;
        b=MPPZzWHNh/HguS5mDdmnZyGaxY+GcinwoOByth9YT+QnE7+/Waua3+w6/sXpLTgP0T
         Rv09OvZZQBCVkBvfBZXKIuXyQFVy3C80Ix9D4MaLWpEzm4LYXz/tNFRugUJfwcYTpA1U
         Ysyqcp6XTCizpuvkrI3Y1X1EexUKslv1GpvD4gDKMpLSpiV74Y/caXb7oRwit6eB2Z8q
         VzLLNZAYiZT39a2RJB6YAbWuRo+u9avPakKIDOyefFgwjr1Z0wE3Z91ROGLIVhojY9+J
         19Z/d0I7UgQOTmdbe5iGSFv5GO3xjIy6RQ/N9a1LScgWM0xFjxvflGOnjDSQNbP2TJ1c
         OqPg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXj6KOssTGWfArVcHQ+uTkL3U52vYMNvqo4r8pVn1lyOTPaS+HyY/zbDKahROCgWzxNeTodHHj/5ISIlFzYFN96XWNSJSsj6A==
X-Gm-Message-State: AOJu0YyohMtdV1S0kYNr4DcLW/FfZRJv6m+qj9iNkOSEgKEeom6bypwF
	iq2lLep7qNwOcIuMuVbNh0K7GZj+8e2OEoeo841qPqjw4WT/ptCt
X-Google-Smtp-Source: AGHT+IGnRZu/uqUZk9u0y88XLRRtLciLmddpM1ZOsLQoGpZG7zLoua4RFgHFPaOcFSHCWklTOBSxpA==
X-Received: by 2002:a05:6a20:d04d:b0:19e:a217:fd20 with SMTP id hv13-20020a056a20d04d00b0019ea217fd20mr1253215pzb.45.1707864373911;
        Tue, 13 Feb 2024 14:46:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:5291:b0:296:a787:cf5f with SMTP id
 si17-20020a17090b529100b00296a787cf5fls2729421pjb.1.-pod-prod-07-us; Tue, 13
 Feb 2024 14:46:13 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUupIEnTyL8RLeZW9/ozOOGfUUp3iE6FNVsoK8prBJ0GaRe5jOuMv038JWfKf0EeMK1fR+VsaoE7obklfIe6Qu/xZ2IQIoCukFiVw==
X-Received: by 2002:a17:90a:fd89:b0:298:cc52:f561 with SMTP id cx9-20020a17090afd8900b00298cc52f561mr923450pjb.14.1707864372816;
        Tue, 13 Feb 2024 14:46:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707864372; cv=none;
        d=google.com; s=arc-20160816;
        b=b9Xk8i2rORJL8Ce6OviJ80ftV9qVHbB0N6bGqZi8dX/znaXj86UAbHQkxJbXWob0x7
         UL6vSlEumRBL9aerIxLGLmDOtjNK367bdHcCUr9dS4htclOPYl0eU3bpJPlKFSqj1UcS
         lTYwhdCwz4AuOk8mABWMKYRmR6/h2CewpNQ0ZquDg2CUqoeBpeOV+oWVyX6feqUulDM6
         07MBnpVPAgrc+4raDvoB1SNAocyRKEx0xE54NldX1ykKiZYTgdbcq6u+QsXXkpXBmZxF
         Tt2rH0tTOqBpJPdt6I1YkAtrH4t93PM0KBTo9eksXzqGl/JHU1/nxTOZxeEyy1duMNHu
         Td3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=m62O428pDtswNs+TJOBUHcO2zhmjFZMBSPfQGCfQJa8=;
        fh=gRiExnEBlrhIJ+6npsf1bpOVnvm80mlA/7Obc2sFF5k=;
        b=y+x4LLdijZZcnRTiWnuyvUFHrtihyDZAFoy6aHi6J5KcvY069nIN/uXIQ55NRjNTha
         hRwmIwd/ijK3iqJUrx2oxqvfPBMfg85xVFZXcYlLf1D5UYGTREh++SZIYU0cPwSN04Au
         XM9z5Y8AiOdnCozQNwT3q0TaJsN0aypaMHUiS8ZZmy0oOe+VpdmPdx7j5sUJhPHG7xgC
         giPwe4TcCh9OZEVRFg7uPr97D8+sC08bQ767vZhIJg128tD9oPGMR2lX1uBKuuufzPZX
         lPiGAnlnDAhAeHK4fyB1M7lVh89xuG22Sd0JRJ2C8vZlkBPcjIIzKefhhi4v3NVKSZAv
         fK1Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=4rjb=jw=goodmis.org=rostedt@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=4RJB=JW=goodmis.org=rostedt@kernel.org"
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id n2-20020a17090a9f0200b0029733c6db6esi157976pjp.1.2024.02.13.14.46.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Feb 2024 14:46:12 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=4rjb=jw=goodmis.org=rostedt@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id E2B1661721;
	Tue, 13 Feb 2024 22:46:11 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 29488C433C7;
	Tue, 13 Feb 2024 22:46:04 +0000 (UTC)
Date: Tue, 13 Feb 2024 17:47:33 -0500
From: Steven Rostedt <rostedt@goodmis.org>
To: Kees Cook <keescook@chromium.org>
Cc: Suren Baghdasaryan <surenb@google.com>, "Darrick J. Wong"
 <djwong@kernel.org>, akpm@linux-foundation.org, kent.overstreet@linux.dev,
 mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
 roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
 willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net,
 void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
 catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
 tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
 x86@kernel.org, peterx@redhat.com, david@redhat.com, axboe@kernel.dk,
 mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org,
 dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
 paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com,
 yuzhao@google.com, dhowells@redhat.com, hughd@google.com,
 andreyknvl@gmail.com, ndesaulniers@google.com, vvvvvv@google.com,
 gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
 vincent.guittot@linaro.org, dietmar.eggemann@arm.com, bsegall@google.com,
 bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
 minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 iommu@lists.linux.dev, linux-arch@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
 linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org
Subject: Re: [PATCH v3 13/35] lib: add allocation tagging support for memory
 allocation profiling
Message-ID: <20240213174733.086b2e3e@gandalf.local.home>
In-Reply-To: <202402131436.2CA91AE@keescook>
References: <20240212213922.783301-1-surenb@google.com>
	<20240212213922.783301-14-surenb@google.com>
	<202402121433.5CC66F34B@keescook>
	<CAJuCfpGU+UhtcWxk7M3diSiz-b7H64_7NMBaKS5dxVdbYWvQqA@mail.gmail.com>
	<20240213222859.GE6184@frogsfrogsfrogs>
	<CAJuCfpGHrCXoK828KkmahJzsO7tJsz=7fKehhkWOT8rj-xsAmA@mail.gmail.com>
	<202402131436.2CA91AE@keescook>
X-Mailer: Claws Mail 3.19.1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=4rjb=jw=goodmis.org=rostedt@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=4RJB=JW=goodmis.org=rostedt@kernel.org"
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

On Tue, 13 Feb 2024 14:38:16 -0800
Kees Cook <keescook@chromium.org> wrote:

> > > Save yourself a cycle of "rework the whole fs interface only to have
> > > someone else tell you no" and put it in debugfs, not sysfs.  Wrangling
> > > with debugfs is easier than all the macro-happy sysfs stuff; you don't
> > > have to integrate with the "device" model; and there is no 'one value
> > > per file' rule.  
> > 
> > Thanks for the input. This file used to be in debugfs but reviewers
> > felt it belonged in /proc if it's to be used in production
> > environments. Some distros (like Android) disable debugfs in
> > production.  
> 
> FWIW, I agree debugfs is not right. If others feel it's right in /proc,
> I certainly won't NAK -- it's just been that we've traditionally been
> trying to avoid continuing to pollute the top-level /proc and instead
> associate new things with something in /sys.

You can create your own file system, but I would suggest using kernfs for it ;-)

If you look in /sys/kernel/ you'll see a bunch of kernel file systems already there:

 ~# mount |grep kernel
 securityfs on /sys/kernel/security type securityfs (rw,nosuid,nodev,noexec,relatime)
 debugfs on /sys/kernel/debug type debugfs (rw,nosuid,nodev,noexec,relatime)
 tracefs on /sys/kernel/tracing type tracefs (rw,nosuid,nodev,noexec,relatime)
 configfs on /sys/kernel/config type configfs (rw,nosuid,nodev,noexec,relatime)

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240213174733.086b2e3e%40gandalf.local.home.
