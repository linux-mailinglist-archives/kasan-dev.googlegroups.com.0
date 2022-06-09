Return-Path: <kasan-dev+bncBCMIZB7QWENRBMPAQ6KQMGQEKFGBEYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9CFEA544CFB
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 15:05:54 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id i26-20020a0565123e1a00b004792c615104sf6646753lfv.12
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 06:05:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654779954; cv=pass;
        d=google.com; s=arc-20160816;
        b=1HvoCJkbVTdoh3GxzD5GutG72cZomxTrblR3KVM3t4Sf6x2vGCXhUX8ilXG4QqEH1P
         MB3bi05R353PBinA0cRQvkVUjhCj0gT1KMoAaxgOX66NiwOZ45O1TVw5W0vkUDqgrHOw
         hbZuXoRm//SqU4w/pv8adZQnAq5D8Mf0p1957r0r5DWqE2kZ4SylsiFwe+/ptoVxc3x/
         hrfVB2kgf3eoFyaObTxaKPYFtLJgnASncBAvFUtIQ2KbqbshuHEcavdwEVwo6DSMt8Ze
         k07U5AKDisyJvLq1EgYQ2BN4/JxsFsWwZ/nPw0/aUkrZRG4Py685PTHKZNDbCSMxliKj
         Fxyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=DnW8OCLY2+PeGxboJoEEv5E5pwIfZV16xa3iMpd/PwM=;
        b=souCap0rDuig9U9nm5V8Hk42/pHrqNVWpRbwbYS1EEiklx1ohqyipkGlsQSLnYFILX
         xm6L2Sv1TGSR+zLGlerTgepmpUIBU0dh6azPX8bhvOE8PcIJK+fw9smnC6erewivuVJ+
         CzKY0b4rHPdQrne25dIDKRpTFkaQ6E7Pxv/HPcM1vowNxamjDwcWF5CKn/2vDGuCyqia
         t0aD8GrpHm57A0pVVzlIewEjunFyvSnu4HDeO3D2N6a/Z6Ysn4cIlx9xZK+MwrlJRVA6
         3j4iy7vCXB1TOTfU1bhRAmHJRm6mnCj1wFwpNjoqIjZbihx4kLJMyb+a76KViW3WVQ0W
         +vrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=X7FFvILg;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DnW8OCLY2+PeGxboJoEEv5E5pwIfZV16xa3iMpd/PwM=;
        b=IHNTNtY1GVBC0FI90mcqcWGq7y5hQK6IAgrCRWMUiHfIbblXkEODArrQ3CAfO68hJC
         Ky0+AD2IEGR2uVA1otpBqcWfR8d0CpsIFv7lem6wfFMAstB5Kg6Jo9vFC75UI/RTd12h
         or5iH2KqlL5ge3feB9e3CLUDeslbF1UP/6Q2xP2QZPt9Ldwu6gMQ0sCCGFUJJaR7TUjn
         F+2BqNeU94WoS/59zfarezUKZKIpwLNdhTQCldVo+idFkdPb8LmqyJjRrjRCE2m03E/S
         UqwfjaV4g0OEmBpH2sIoomHHYPXlNBcxz0T8k8NKYZ+Yt7FKVC+ez4Aa+sU9UR86eGvo
         bx2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DnW8OCLY2+PeGxboJoEEv5E5pwIfZV16xa3iMpd/PwM=;
        b=J4JbWhAcMvjNY9LhmGwx0W7PaMBX2OU12kH8u0ubTqhfszAjK4Ce6NXALPVW/1GG90
         eJE7n+MaW4VDMTp1mZYeHOylJII83QrKY1ce46k0s6c8/5aFxmMpUsMtE6o5jemYAuBT
         DlWvrSBkE9rFAi0W0D67MnBaCVBVM9pJWC6AnG1N5X/BwnRRzmU9m/HsRmVilesXyKam
         DFmhkE30XmOBDpill96HEKE7siYL6ys6sY6YI/STp1DfvRL8Oyhfs4BaFVmNWfn8Dpme
         2h4WLf/GXWmNtRdOt8xG/Zzt8WLbRP9SrIs8oZ0l/+LLuaTQDdXDz8RzGSWZnCOxh/T5
         qt2Q==
X-Gm-Message-State: AOAM533Ybxb+/wGlPUlJCnJFEUfflsF4dQVt5ERawJOqT2I99dL8RSnI
	Mi7rAhppHKma8WeOUrmfqBY=
X-Google-Smtp-Source: ABdhPJxiPy/ucBsEadw9RtxgV2Q/6GY3NUaLPAC/WGq9wnP8kxmT4dGkqn72vbfWVBvLN/gZtjPf0w==
X-Received: by 2002:a05:6512:987:b0:479:3983:e744 with SMTP id w7-20020a056512098700b004793983e744mr13941367lft.402.1654779953975;
        Thu, 09 Jun 2022 06:05:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:81c8:0:b0:255:7bff:427d with SMTP id s8-20020a2e81c8000000b002557bff427dls853734ljg.0.gmail;
 Thu, 09 Jun 2022 06:05:52 -0700 (PDT)
X-Received: by 2002:a2e:6817:0:b0:258:b235:7812 with SMTP id c23-20020a2e6817000000b00258b2357812mr1201846lja.83.1654779952730;
        Thu, 09 Jun 2022 06:05:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654779952; cv=none;
        d=google.com; s=arc-20160816;
        b=0HQi95tWTZf8ItWzlCmoNr6W978shY+HgkWTOg3M6Nu/10LThRGUK3T4k7F4UyA2Z3
         03k9jJq7M9IFC1H1mAFlsL49DYNgibpmRjilhO4Y2lWJadQzFrTU3A1oS6udqHOMpQZk
         FeRp/uj3yn7p33nxw0niY8TK6e29uo+0Tj5aO6KTJAjKn7CkwjlSqkMoT7Pa59qrZtWL
         qVshfC+PBo7w2pgYFypd2mVVkmuF0bfO7v3qIGqE08mmeAJsoIs8pF0m1pg16kr2+nMF
         BjSlr23d8aYVJquOkbpQTsuU0JtUovqCbpj6LzE1Ppqyo+M8CTF2JvRfmll2EIjSPpqh
         J1Rg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xOQI9nYJjsWx7RUNIP4XR5dRmZHTAqrUHXmWvjF6nBY=;
        b=Mj4FnGHopODwMIZWx1ADszJAHQzzytbwATgswE9nLnfBLH7aH+UDmLIPQ9NfcpYrHM
         +BL+34VEzt+wLWwiWhqVBs95YlJVr0h2ehIrqJwyha26C1cHtOpi+Kjdy8iaM2rqaHhB
         IaYEslhg9BbHSEEvST77j3hcdMToywQ6B2itMmEL0Kj6+oF7/Si3dHICkS7QWqNkVyu9
         JL8CyZC+d24SGtEtyBAUBYIitza6ZW9qxGrq90HcCXdcVytpi9dzZ5YWFOgoX1aPbuiV
         /2HSEAippDMNDf9erVfzWHOMua3ftVk7uIcFjcofxyeFSlViOgwSlABVXqwnclSZlsOw
         bt5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=X7FFvILg;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x134.google.com (mail-lf1-x134.google.com. [2a00:1450:4864:20::134])
        by gmr-mx.google.com with ESMTPS id x24-20020a056512131800b004786caccd4esi1229423lfu.4.2022.06.09.06.05.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 06:05:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134 as permitted sender) client-ip=2a00:1450:4864:20::134;
Received: by mail-lf1-x134.google.com with SMTP id a15so37869689lfb.9
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 06:05:52 -0700 (PDT)
X-Received: by 2002:ac2:4f11:0:b0:479:3554:79d with SMTP id
 k17-20020ac24f11000000b004793554079dmr15389711lfr.417.1654779952199; Thu, 09
 Jun 2022 06:05:52 -0700 (PDT)
MIME-Version: 1.0
References: <20220609113046.780504-1-elver@google.com> <20220609113046.780504-2-elver@google.com>
 <CACT4Y+ZfjLCj=wvPFhyUQLwxmcOXuK9G_a53SB=-niySExQdew@mail.gmail.com> <YqHtLvdLvdM5Lmdh@elver.google.com>
In-Reply-To: <YqHtLvdLvdM5Lmdh@elver.google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Jun 2022 15:05:40 +0200
Message-ID: <CACT4Y+YWrzpdTnbcvhBb3GfZ-0GmCZuvErFZbh5abNHAV+7WZQ@mail.gmail.com>
Subject: Re: [PATCH 1/8] perf/hw_breakpoint: Optimize list of per-task breakpoints
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Frederic Weisbecker <frederic@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, linux-perf-users@vger.kernel.org, x86@kernel.org, 
	linux-sh@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=X7FFvILg;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, 9 Jun 2022 at 14:53, Marco Elver <elver@google.com> wrote:
>
> On Thu, Jun 09, 2022 at 02:30PM +0200, Dmitry Vyukov wrote:
> [...]
> > > +       rcu_read_lock();
> >
> > Why do we need rcu_read_lock() here?
> > The patch does not change anything with respect to locking, so all
> > accesses to the container should still be protected by nr_bp_mutex.
> > Similarly for the rcu variant of for_each below.
> [...]
> > > +       head = rhltable_lookup(&task_bps_ht, &bp->hw.target, task_bps_ht_params);
> > > +       if (!head)
> > > +               goto out;
> > > +
> > > +       rhl_for_each_entry_rcu(iter, pos, head, hw.bp_list) {
>
> It's part of rhashtable's interface requirements:
>
>         /**
>          * rhltable_lookup - search hash list table
>          * @hlt:        hash table
>          * @key:        the pointer to the key
>          * @params:     hash table parameters
>          *
>          * Computes the hash value for the key and traverses the bucket chain looking
>          * for a entry with an identical key.  All matching entries are returned
>          * in a list.
>          *
>          * This must only be called under the RCU read lock.
>          *
>          * Returns the list of entries that match the given key.
>          */
>
> Beyond that, even though there might not appear to be any concurrent
> rhashtable modifications, it'll be allowed in patch 6/8. Furthermore,
> rhashtable actually does concurrent background compactions since I
> selected 'automatic_shrinking = true' (so we don't leak tons of memory
> after starting and killing those 1000s of tasks) -- there's this
> call_rcu() in lib/rhashtable.c that looks like that's when it's used.
> This work is done in a deferred work by rht_deferred_worker().


I see. Thanks.

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYWrzpdTnbcvhBb3GfZ-0GmCZuvErFZbh5abNHAV%2B7WZQ%40mail.gmail.com.
