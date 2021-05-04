Return-Path: <kasan-dev+bncBCALX3WVYQORB5XGYWCAMGQEXIGP7YY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 256DC372DD7
	for <lists+kasan-dev@lfdr.de>; Tue,  4 May 2021 18:16:55 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id s4-20020ac85cc40000b02901b59d9c0986sf3904469qta.19
        for <lists+kasan-dev@lfdr.de>; Tue, 04 May 2021 09:16:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620145014; cv=pass;
        d=google.com; s=arc-20160816;
        b=UPFO6Yd5OwSJC01DBYXZLosqetnvV6i0MXyFeT2kcVpUlMChYu5rd6cbMrlTLDPRg3
         ET6NGf32ZPMNWM2KbfwKsDzxsVhQyATx7du03il5Y9WYKbK4CeXTgKqwZc8KKPqmkJx4
         QT74hM21x8W+ThdNIrRwZVShoYhA3cxe7z6CvTE99KMzSO67nZnhvWjF53RVrY+7JiEK
         cpa2wKoQncRHgRJOCs4UZJdERiEJHdRELe548WNyNyy+SyrCXa993nhgsVECqtywrG32
         FjIfv58/lEWXTnD/exrOdUxPmRDZThNGujETYynWlZLHnGuoxRwu2ngbfazafW5xNCPV
         x8kQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=S4afchdvdFMpN9JVbtXCXnxITGjINanJF6gOhe9yFNM=;
        b=OeoaOuptolmmWH02xnK+LjKi0DhcxE3NsZpLy3MagdGRlOqAgceZjHLhxMCXBQFRsk
         dkhBOCB8Qt0X9iFzY1xisV/ZPvMdDDGDKOIf/DTya+jD4jdvrhLrk44uy87ivf+x0ktn
         2NiJL3tpq9bjGBfZLxoMx0Fw2B5PawmIrgEl4JN9OHKJulf3K+kpHh/Z9E4ZZcIec4Yz
         VFcHLUJmcA2kOvHWw2byZ0uYlV4cyPIK4ORvkhd6K3aUVuZXJPxnsIE+rzIPUNj9ekDi
         W3qRkEM/UqvZMboR/JG+AQHtYVKp6PyDChswQ1e7P5Fk24aNvmqFw/qcncONx2jm8fXi
         lkvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=S4afchdvdFMpN9JVbtXCXnxITGjINanJF6gOhe9yFNM=;
        b=DxFyPLEbFLZKjLu762R1Zkwz6JnyGxo669Mp7ty0n83/a4T/7ZI0exGeHVkEN+TzmK
         ygVYLNAxKBltAqL8XCujimNn0i/WfKKUXfoqnT3yNxno/bM2zcDf6wJJC4Q0Io7BN5vi
         W4Hp1X7VD9UyZDq0gCN+iuHMcRejDJUOSx54qziIsA3gwHiGkmh4aBrOSkCoLImkjnz5
         rSP+0UsOo2QUhsCqMToRMPbTv2Rvur4/nJU5eVgorhWJjQyfngdtst3fx4A88+soM4Vc
         cYLg30kD7avKXwm67zfA4J57xnT4tTXxCPdjSNMO06CkiB/vQlrYkDeAedl1zSIII7n/
         0Dpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S4afchdvdFMpN9JVbtXCXnxITGjINanJF6gOhe9yFNM=;
        b=bz7z6OL6m9WH4N8V8dFrAS7HpCi4qH+OIu3wxELErRrjErjtkd40DgviOUfLbGM49k
         fQ8VqbTlmQk0GiOCaaZv4hKY/ZVOPh6tFIi3V154W+7DezPiYRE8L4gG9E6GeoOs+bjh
         84M3VYyyYufus9IVeneGDG1zAFQcA1OX2BKwf/hjdXXBiOZqvuFcXIjmKpbkqDwTo8te
         UY8RsEqQDjXlOckc2z5pIfXmGiHpb1DR3D7MwN4kByzpAFanfoMriNif5yMB3QH5/rDz
         b/e4Lu5T0MIej6XTG002ZFJ+BRmgQ1r/3hAqfTbvMRZGYsdY09MptwD5sLiiCmHhyiU2
         A6mg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531WNOl2qMtYZ5ORpr1GInVJkWq4YxUrIJ4+250IVbk+egw9KKxh
	bHVNh119OmXLyFxUdNkVy3o=
X-Google-Smtp-Source: ABdhPJwlrK3d/TvNDQO+uXFbwNDVX0JSOhXWg+wUHFcdWA2qWK1VwVXsIn08CNVVkoHH0y1Bq0Wv5A==
X-Received: by 2002:a37:a854:: with SMTP id r81mr10323865qke.83.1620145014190;
        Tue, 04 May 2021 09:16:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:f28a:: with SMTP id k10ls5440585qvl.3.gmail; Tue, 04 May
 2021 09:16:53 -0700 (PDT)
X-Received: by 2002:ad4:4dc8:: with SMTP id cw8mr12521369qvb.16.1620145013770;
        Tue, 04 May 2021 09:16:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620145013; cv=none;
        d=google.com; s=arc-20160816;
        b=wzZ+EPHtGv+EzWuNS/TceNQNuCE07Qtfau3IFdZPEtWRwsXGVTo/zaygYaP4VmZ+Kg
         n+ESe32eFsDN3yl2KBeoaG7JJhWnptBpqXo9GGWsuWBUMC4REnI3W5Vpi9hjsILGSpvP
         LzK2xXksBNWuUV7ejKT4oG6FNdiCU52d+FUT0HiBNUkQysldX+nHegtQfgpdTMywy9vn
         0G1iPfEOytLh/GpniahmXmZ89+Bxcxq/TZEM6fzPdoDa+D/gfM6grbSx0VQNI8MzK+hD
         Ee8X0Drk8fg3xbWhQiahRNa3QUMmF2TJfXA51b9hd1M3EJc6eYv2CYIFsgshx8saEmuc
         L23A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=a6qjfnP/Aok4fyl3z9I9QNljc+OifzT6r5oC8UxTV18=;
        b=s+LqONpS0mNswe2WIe6cXNHW16tEGesyaeZMxFNtoAwWBfkBG4flSjln4Eb2bSvqwR
         tZ8P3SHtv0w6qqBO7V70lpgobDtMXWiH2qJE2/QtQemNA6b7MN6MNjUncOswx1rzQjPt
         QRO+wDv0MIfQN6ud2wQKkHPzOnxQ980tJS9Yx9PjLcPzqVa1z3bDADJ6olcOB9VG0+cx
         EOy1/4rsd2oyihw8gXdeqC6vNCIAnQn6JllrId4vj+RYpVCGyuMbBWIo0n5ykRjIzdRB
         RosSrelcy5ysIdH60vYTSKGzCPdUz4iv6Lpu7w3tEl7JbpnyIUSKqTzndJPC+IlUhZ7h
         ONfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out01.mta.xmission.com (out01.mta.xmission.com. [166.70.13.231])
        by gmr-mx.google.com with ESMTPS id k1si463571qtg.2.2021.05.04.09.16.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 04 May 2021 09:16:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) client-ip=166.70.13.231;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out01.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1ldxj7-0016mO-3L; Tue, 04 May 2021 10:16:49 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.xmission.com)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1ldxj5-00GMeL-GN; Tue, 04 May 2021 10:16:48 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Marco Elver <elver@google.com>
Cc: Peter Collingbourne <pcc@google.com>,  Arnd Bergmann <arnd@arndb.de>,  Florian Weimer <fweimer@redhat.com>,  "David S. Miller" <davem@davemloft.net>,  Peter Zijlstra <peterz@infradead.org>,  Ingo Molnar <mingo@kernel.org>,  Thomas Gleixner <tglx@linutronix.de>,  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>,  sparclinux <sparclinux@vger.kernel.org>,  linux-arch <linux-arch@vger.kernel.org>,  Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,  Linux API <linux-api@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>
References: <m14kfjh8et.fsf_-_@fess.ebiederm.org>
	<20210503203814.25487-1-ebiederm@xmission.com>
	<20210503203814.25487-10-ebiederm@xmission.com>
	<m1o8drfs1m.fsf@fess.ebiederm.org>
	<CANpmjNNOK6Mkxkjx5nD-t-yPQ-oYtaW5Xui=hi3kpY_-Y0=2JA@mail.gmail.com>
	<m1lf8vb1w8.fsf@fess.ebiederm.org>
	<CAMn1gO7+wMzHoGtp2t3=jJxRmPAGEbhnUDFLQQ0vFXZ2NP8stg@mail.gmail.com>
	<YJEZdhe6JGFNYlum@elver.google.com>
Date: Tue, 04 May 2021 11:16:43 -0500
In-Reply-To: <YJEZdhe6JGFNYlum@elver.google.com> (Marco Elver's message of
	"Tue, 4 May 2021 11:52:54 +0200")
Message-ID: <m1im3ya2z8.fsf@fess.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1ldxj5-00GMeL-GN;;;mid=<m1im3ya2z8.fsf@fess.ebiederm.org>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX1+LzdVYRglNd0Xkn7k8K8l9BDDFZViEpes=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa06.xmission.com
X-Spam-Level: *
X-Spam-Status: No, score=1.9 required=8.0 tests=ALL_TRUSTED,BAYES_05,
	DCC_CHECK_NEGATIVE,T_TM2_M_HEADER_IN_MSG,XMNoVowels,XMSubLong,
	XM_B_SpammyWords,XM_Body_Dirty_Words autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	* -0.5 BAYES_05 BODY: Bayes spam probability is 1 to 5%
	*      [score: 0.0158]
	*  1.5 XMNoVowels Alpha-numberic number with no vowels
	*  0.7 XMSubLong Long Subject
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa06 1397; Body=1 Fuz1=1 Fuz2=1]
	*  1.0 XM_Body_Dirty_Words Contains a dirty word
	*  0.2 XM_B_SpammyWords One or more commonly used spammy words
X-Spam-DCC: XMission; sa06 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: *;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 980 ms - load_scoreonly_sql: 0.03 (0.0%),
	signal_user_changed: 9 (0.9%), b_tie_ro: 8 (0.8%), parse: 1.00 (0.1%),
	extract_message_metadata: 14 (1.4%), get_uri_detail_list: 4.0 (0.4%),
	tests_pri_-1000: 13 (1.3%), tests_pri_-950: 1.24 (0.1%),
	tests_pri_-900: 1.02 (0.1%), tests_pri_-90: 250 (25.5%), check_bayes:
	248 (25.3%), b_tokenize: 14 (1.5%), b_tok_get_all: 12 (1.3%),
	b_comp_prob: 4.8 (0.5%), b_tok_touch_all: 208 (21.2%), b_finish: 4.9
	(0.5%), tests_pri_0: 672 (68.6%), check_dkim_signature: 0.84 (0.1%),
	check_dkim_adsp: 2.4 (0.2%), poll_dns_idle: 0.54 (0.1%), tests_pri_10:
	2.6 (0.3%), tests_pri_500: 13 (1.3%), rewrite_mail: 0.00 (0.0%)
Subject: Re: [PATCH 10/12] signal: Redefine signinfo so 64bit fields are possible
X-SA-Exim-Version: 4.2.1 (built Sat, 08 Feb 2020 21:53:50 +0000)
X-SA-Exim-Scanned: Yes (on in02.mta.xmission.com)
X-Original-Sender: ebiederm@xmission.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as
 permitted sender) smtp.mailfrom=ebiederm@xmission.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=xmission.com
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

Marco Elver <elver@google.com> writes:

> On Mon, May 03, 2021 at 09:03PM -0700, Peter Collingbourne wrote:
>> On Mon, May 3, 2021 at 8:42 PM Eric W. Biederman <ebiederm@xmission.com> wrote:
>> > Marco Elver <elver@google.com> writes:
>> > > On Mon, 3 May 2021 at 23:04, Eric W. Biederman <ebiederm@xmission.com> wrote:
>> > >> "Eric W. Beiderman" <ebiederm@xmission.com> writes:
>> > >> > From: "Eric W. Biederman" <ebiederm@xmission.com>
>> > >> >
>> > >> > The si_perf code really wants to add a u64 field.  This change enables
>> > >> > that by reorganizing the definition of siginfo_t, so that a 64bit
>> > >> > field can be added without increasing the alignment of other fields.
>> > >
>> > > If you can, it'd be good to have an explanation for this, because it's
>> > > not at all obvious -- some future archeologist will wonder how we ever
>> > > came up with this definition of siginfo...
>> > >
>> > > (I see the trick here is that before the union would have changed
>> > > alignment, introducing padding after the 3 ints -- but now because the
>> > > 3 ints are inside the union the union's padding no longer adds padding
>> > > for these ints.  Perhaps you can explain it better than I can. Also
>> > > see below.)
>> >
>> > Yes.  The big idea is adding a 64bit field into the second union
>> > in the _sigfault case will increase the alignment of that second
>> > union to 64bit.
>> >
>> > In the 64bit case the alignment is already 64bit so it is not an
>> > issue.
>> >
>> > In the 32bit case there are 3 ints followed by a pointer.  When the
>> > 64bit member is added the alignment of _segfault becomes 64bit.  That
>> > 64bit alignment after 3 ints changes the location of the 32bit pointer.
>> >
>> > By moving the 3 preceding ints into _segfault that does not happen.
>> >
>> >
>> >
>> > There remains one very subtle issue that I think isn't a problem
>> > but I would appreciate someone else double checking me.
>> >
>> >
>> > The old definition of siginfo_t on 32bit almost certainly had 32bit
>> > alignment.  With the addition of a 64bit member siginfo_t gains 64bit
>> > alignment.  This difference only matters if the 64bit field is accessed.
>> > Accessing a 64bit field with 32bit alignment will cause unaligned access
>> > exceptions on some (most?) architectures.
>> >
>> > For the 64bit field to be accessed the code needs to be recompiled with
>> > the new headers.  Which implies that when everything is recompiled
>> > siginfo_t will become 64bit aligned.
>> >
>> >
>> > So the change should be safe unless someone is casting something with
>> > 32bit alignment into siginfo_t.
>> 
>> How about if someone has a field of type siginfo_t as an element of a
>> struct? For example:
>> 
>> struct foo {
>>   int x;
>>   siginfo_t y;
>> };
>> 
>> With this change wouldn't the y field move from offset 4 to offset 8?
>
> This is a problem if such a struct is part of the ABI -- in the kernel I
> found these that might be problematic:
>
> | arch/csky/kernel/signal.c:struct rt_sigframe {
> | arch/csky/kernel/signal.c-	/*
> | arch/csky/kernel/signal.c-	 * pad[3] is compatible with the same struct defined in
> | arch/csky/kernel/signal.c-	 * gcc/libgcc/config/csky/linux-unwind.h
> | arch/csky/kernel/signal.c-	 */
> | arch/csky/kernel/signal.c-	int pad[3];
> | arch/csky/kernel/signal.c-	struct siginfo info;
> | arch/csky/kernel/signal.c-	struct ucontext uc;
> | arch/csky/kernel/signal.c-};
> | [...]
> | arch/parisc/include/asm/rt_sigframe.h-#define SIGRETURN_TRAMP 4
> | arch/parisc/include/asm/rt_sigframe.h-#define SIGRESTARTBLOCK_TRAMP 5 
> | arch/parisc/include/asm/rt_sigframe.h-#define TRAMP_SIZE (SIGRETURN_TRAMP + SIGRESTARTBLOCK_TRAMP)
> | arch/parisc/include/asm/rt_sigframe.h-
> | arch/parisc/include/asm/rt_sigframe.h:struct rt_sigframe {
> | arch/parisc/include/asm/rt_sigframe.h-	/* XXX: Must match trampoline size in arch/parisc/kernel/signal.c 
> | arch/parisc/include/asm/rt_sigframe.h-	        Secondary to that it must protect the ERESTART_RESTARTBLOCK
> | arch/parisc/include/asm/rt_sigframe.h-		trampoline we left on the stack (we were bad and didn't 
> | arch/parisc/include/asm/rt_sigframe.h-		change sp so we could run really fast.) */
> | arch/parisc/include/asm/rt_sigframe.h-	unsigned int tramp[TRAMP_SIZE];
> | arch/parisc/include/asm/rt_sigframe.h-	struct siginfo info;
> | [..]
> | arch/parisc/kernel/signal32.h-#define COMPAT_SIGRETURN_TRAMP 4
> | arch/parisc/kernel/signal32.h-#define COMPAT_SIGRESTARTBLOCK_TRAMP 5
> | arch/parisc/kernel/signal32.h-#define COMPAT_TRAMP_SIZE (COMPAT_SIGRETURN_TRAMP + \
> | arch/parisc/kernel/signal32.h-				COMPAT_SIGRESTARTBLOCK_TRAMP)
> | arch/parisc/kernel/signal32.h-
> | arch/parisc/kernel/signal32.h:struct compat_rt_sigframe {
> | arch/parisc/kernel/signal32.h-        /* XXX: Must match trampoline size in arch/parisc/kernel/signal.c
> | arch/parisc/kernel/signal32.h-                Secondary to that it must protect the ERESTART_RESTARTBLOCK
> | arch/parisc/kernel/signal32.h-                trampoline we left on the stack (we were bad and didn't
> | arch/parisc/kernel/signal32.h-                change sp so we could run really fast.) */
> | arch/parisc/kernel/signal32.h-        compat_uint_t tramp[COMPAT_TRAMP_SIZE];
> | arch/parisc/kernel/signal32.h-        compat_siginfo_t info;
>
> Adding these static asserts to parisc shows the problem:
>
> | diff --git a/arch/parisc/kernel/signal.c b/arch/parisc/kernel/signal.c
> | index fb1e94a3982b..0be582fb81be 100644
> | --- a/arch/parisc/kernel/signal.c
> | +++ b/arch/parisc/kernel/signal.c
> | @@ -610,3 +610,6 @@ void do_notify_resume(struct pt_regs *regs, long in_syscall)
> |  	if (test_thread_flag(TIF_NOTIFY_RESUME))
> |  		tracehook_notify_resume(regs);
> |  }
> | +
> | +static_assert(sizeof(unsigned long) == 4); // 32 bit build
> | +static_assert(offsetof(struct rt_sigframe, info) == 9 * 4);
>
> This passes without the siginfo rework in this patch. With it:
>
> | ./include/linux/build_bug.h:78:41: error: static assertion failed: "offsetof(struct rt_sigframe, info) == 9 * 4"
>
> As sad as it is, I don't think we can have our cake and eat it, too. :-(
>
> Unless you see why this is fine, I think we need to drop this patch and
> go back to the simpler version you had.

No.  I really can't.  I think we are stuck with 32bit alignment on 32bit
architectures at this point.  Which precludes 32bit architectures from
including a 64bit field.

The variant of this that concerns me the most is siginfo_t embedded in a
structure in a library combined with code that is compiled with new
headers.  The offset of the embedded siginfo_t could very easily change
and break things.

That makes the alignment an ABI property we can't mess with.  Shame.

I will figure out some static asserts to verify this property remains
on 32bit and respin this series.

Eric

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/m1im3ya2z8.fsf%40fess.ebiederm.org.
