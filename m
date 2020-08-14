Return-Path: <kasan-dev+bncBDV37XP3XYDRBYHK3H4QKGQEQDK3CKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C3782448CB
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 13:28:34 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id y7sf5950310qvj.11
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 04:28:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597404513; cv=pass;
        d=google.com; s=arc-20160816;
        b=NrPvVTBjhzTBRdtu39tJMRBPKOiXrrbwNR+sPdl3mohbhiEeC4Jr/TRXvjotxSv/1S
         7GJ8LOdFZJ8PU+0RZkMtY/Ktb4qU87zCOzpQO7GRBoRM1Rbf3lNOnxLNmgsaSzTnPXR+
         U4E25gAmTxsdL4flF+gpGKKEX4+mQFxuNDudcqBUweB8Yl+Bd380RUiQbWFVw4QI7eMz
         9spKVqW4X83IphlC+gr221HU9Gt3v22u9Ho06lBxDERZafr5q4R9jTyQUtee+NDiBZEC
         eoconD7aE0IjMNB8C1wl0Z64GTm5G5iNytxuCHXJ4j5E66Y0QWznvVQ/4eU+RmdJvl2R
         sdbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=j6VPFaAoevVA3/mjT3073yB1XikLCFUP0r0G8hx713E=;
        b=NH8wQ3VX/4mu9G8y/nNdTZYIq5fmTWx9UaDU90wowVz7c41dsEdSr0ah0nijjpzP+5
         /vhp/H8KLXVPv8nh4gMukyjTka56J0nx7VlAyBa3o/VvmaVMIr6r9JFO+c8R8yHxTfbQ
         54ZcHqWwja1ELmss81He9vNtpvSdtKhyT8jOeQ5UkplhGI/6RYhbl00Anz2FWusx37g3
         kCbxqrHPbFKTjVq37ccbRHW9I2EUQIqI2YWrfNgRhEDAzUtslZPXjiT3EIHZ4ZB6hGii
         nr2z1V6nRQ7Vqg8FnyEtgFv39tUP0puFjEStceZQucUBFZA+DVINDs1vW8qTHRtNsrov
         z+rA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=j6VPFaAoevVA3/mjT3073yB1XikLCFUP0r0G8hx713E=;
        b=iZClKVXUqOqi9ugbsjt5MgkxqPxGZ9DXnzBu3jzkDjKLfK1tbqX+YoPdQLR5lqqb0l
         gI/p/1EU/tMMlMUNsZ7i4ZV3lrNjaHUxyFYy4Gj67CycKy66MCb7YXd2ZKtg1WgzccPI
         gTWPUaizi10KUdspgmXOutzVd1+sGb60wznVoTWd50GQN3QRagFQkzHIL5ioCt/Hdrt1
         R0aGfWr2oGYJsZQi4YoAOWfjVRLGwF+Yo/+SdCdSr7coCGNzfbfF8TWYR+yNNr4r/B/Q
         yIHLcXuAx94DkksYHjUz7/kzlXTTZCWxRQhH30Vs9MhbA6NyQLbXp5zAiKB2b1ArDU7m
         Ud9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=j6VPFaAoevVA3/mjT3073yB1XikLCFUP0r0G8hx713E=;
        b=RDUDmr+g6c7Da3S7h017BzfaO10EIgOTNlL5apXqjofVz5wJR4rvQViL82THhN2Q/K
         FigCtnkkPte7eQSQGNKr7lRot3LFbfhvjlg9GVfKNZRf5z6I20u5E6JrQPPbN6Swi5UE
         jYXvYS7+LiFd+8+HEkAisJ8gpX+otoRZD0/vPiFAR14UWRoud5+bZ9duDH7BABG2hFU6
         5sPDFYyxK8pKnhA3zl7Ai6YgRkgR6vj88RhA714sBicPuPL561WTw+7zDRRplc/2SIzz
         ujgslenp9qE/lb2UeVBKM3NHdWBFLvzStSay1uA6OOm4AduFUx9AuQpmvC2Lgo/bQrj6
         rkxw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532JxFtdkPLZNTYOs5rIg5l+6OGPd5Z3geUVceUHlnia0hKQhqcQ
	5Q+B0LL82MvATfunBHuMgzo=
X-Google-Smtp-Source: ABdhPJwSiIWtmQ3Tou4amAYrv4MALUsGMuz3Ky19fcO+1kDkh/XuBfmRE1z6qIiOuSz/iGTlShb9pQ==
X-Received: by 2002:a37:5fc4:: with SMTP id t187mr1636063qkb.224.1597404512886;
        Fri, 14 Aug 2020 04:28:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4863:: with SMTP id u3ls2139807qvy.2.gmail; Fri, 14 Aug
 2020 04:28:32 -0700 (PDT)
X-Received: by 2002:a0c:d64b:: with SMTP id e11mr2154550qvj.169.1597404512557;
        Fri, 14 Aug 2020 04:28:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597404512; cv=none;
        d=google.com; s=arc-20160816;
        b=t/Pwh3Act4Z5x49HAhva9vqrtrlEVTOAAMxeaK9m9GH7d8cIvI0J6op05RFMrm96R3
         MX7f9vvF3BMMml4s1puaG09iNA+s8vf1VJ8qOs32hUblE+Rpjzt2wmEUKrEME7GBjO07
         UiVX4N/GADoeDKl7ylRwwl19DBFHtx9DlZROmsiD6I8BhCuIqi4FhgxWf5CWHadf0LN2
         sG2+n9+8zH/6bz2cHA76xaaRsAl1Y6SvAbfoWsmXjgSpdIRfmnIWTKGPTMjwTW9P6nxD
         La2VZZ4QLz8+HakDnZjMvd93ZxSdJTn15AnbqkndvOXetOiLeT5R4z65Kd7/rwCQaHb4
         na8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=ha+SI8q5lladiwXinHPEDCpxemW6nJJ/A8LF9/w9W4E=;
        b=FbdAEz+I7JYerVmVB1DM9T+61qUl0tBJfkS8r7dtXzRnPLPLfObDip4fkFYWsJOpk8
         6uoA6eHwHnyIFgoZcaMtLG9GEXLjmKLeGxYamPreGMSaYn3iBV5lGcfzW1rgHBv+ayGW
         RqaBKGN48aQM9PlIyuqdwBtWLl6V7+bvFxsO4PZabdunHKUdJep1qRtTyLXuS+aa6a9d
         jQ/vkdZSVCogl8rbHuzmE4e7MYHBaZG1wzMH58x2k1Q6tJmhub7KUED3Yo25qs7JbY12
         L+BeShLqWjj/FlEth5pXrzjesCo5u2rmx9PNAa37Dsis4TOYnqEHKLZYUrBrFsN5EZbB
         rxJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id m13si535743qtn.0.2020.08.14.04.28.32
        for <kasan-dev@googlegroups.com>;
        Fri, 14 Aug 2020 04:28:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 9919B1063;
	Fri, 14 Aug 2020 04:28:31 -0700 (PDT)
Received: from C02TD0UTHF1T.local (unknown [10.57.33.165])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 5A90F3F6CF;
	Fri, 14 Aug 2020 04:28:29 -0700 (PDT)
Date: Fri, 14 Aug 2020 12:28:26 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Will Deacon <will@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	linux-arch <linux-arch@vger.kernel.org>
Subject: Re: [PATCH 8/8] locking/atomics: Use read-write instrumentation for
 atomic RMWs
Message-ID: <20200814112826.GB68877@C02TD0UTHF1T.local>
References: <20200721103016.3287832-1-elver@google.com>
 <20200721103016.3287832-9-elver@google.com>
 <20200721141859.GC10769@hirez.programming.kicks-ass.net>
 <CANpmjNM6C6QtrtLhRkbmfc3jLqYaQOvvM_vKA6UyrkWadkdzNQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNM6C6QtrtLhRkbmfc3jLqYaQOvvM_vKA6UyrkWadkdzNQ@mail.gmail.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

Hi,

Sorry to come to this rather late -- this comment equally applies to v2
so I'm replying here to have context.

On Wed, Jul 22, 2020 at 12:11:18PM +0200, Marco Elver wrote:
> On Tue, 21 Jul 2020 at 16:19, Peter Zijlstra <peterz@infradead.org> wrote:
> >
> > On Tue, Jul 21, 2020 at 12:30:16PM +0200, Marco Elver wrote:
> >
> > > diff --git a/scripts/atomic/gen-atomic-instrumented.sh b/scripts/atomic/gen-atomic-instrumented.sh
> > > index 6afadf73da17..5cdcce703660 100755
> > > --- a/scripts/atomic/gen-atomic-instrumented.sh
> > > +++ b/scripts/atomic/gen-atomic-instrumented.sh
> > > @@ -5,9 +5,10 @@ ATOMICDIR=$(dirname $0)
> > >
> > >  . ${ATOMICDIR}/atomic-tbl.sh
> > >
> > > -#gen_param_check(arg)
> > > +#gen_param_check(meta, arg)
> > >  gen_param_check()
> > >  {
> > > +     local meta="$1"; shift
> > >       local arg="$1"; shift
> > >       local type="${arg%%:*}"
> > >       local name="$(gen_param_name "${arg}")"
> > > @@ -17,17 +18,24 @@ gen_param_check()
> > >       i) return;;
> > >       esac
> > >
> > > -     # We don't write to constant parameters
> > > -     [ ${type#c} != ${type} ] && rw="read"
> > > +     if [ ${type#c} != ${type} ]; then
> > > +             # We don't write to constant parameters
> > > +             rw="read"
> > > +     elif [ "${meta}" != "s" ]; then
> > > +             # Atomic RMW
> > > +             rw="read_write"
> > > +     fi
> >
> > If we have meta, should we then not be consistent and use it for read
> > too? Mark?
> 
> gen_param_check seems to want to generate an 'instrument_' check per
> pointer argument. So if we have 1 argument that is a constant pointer,
> and one that isn't, it should generate different instrumentation for
> each. By checking the argument type, we get that behaviour. Although
> we are making the assumption that if meta indicates it's not a 's'tore
> (with void return), it's always a read-write access on all non-const
> pointers.
> 
> Switching over to checking only meta would always generate the same
> 'instrument_' call for each argument. Although right now that would
> seem to work because we don't yet have an atomic that accepts a
> constant pointer and a non-const one.
> 
> Preferences?

Given the only non-rmw cases use the 'l' and 's' meta values, and those
only have a single argument, I reckon it's preferable to special-case
those specifically, e.g.

	case "{meta}" in
	l) rw="read";;	
	s) rw="write";;
	*) rw="read_write";;
	esac

... then we can rework that in future if we ever need to handle multiple
atomic variables that have distinct r/w/rw access types.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200814112826.GB68877%40C02TD0UTHF1T.local.
