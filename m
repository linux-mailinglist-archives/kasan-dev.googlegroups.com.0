Return-Path: <kasan-dev+bncBCMIZB7QWENRBTHKUTXAKGQECFME3TA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E3B6F71B8
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Nov 2019 11:17:50 +0100 (CET)
Received: by mail-qk1-x740.google.com with SMTP id d144sf7373625qke.16
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Nov 2019 02:17:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573467469; cv=pass;
        d=google.com; s=arc-20160816;
        b=XRMQffqT7CwLJ8f60nEq8d5JrpdS3rETsWVFJ9OBI2Lf8K+4xImAX/0ZA5DQzNc7kc
         ELD0CjAqS09R6J/wex3kBi/etOwmmXLrC6uXmkWguK4TNg8nntNPcRG2ZAr6kSC/l+Uc
         0Epo7buwP53IWGvgqqUKuvuHRGG9z8KbHZi2mBOa2DU5cC0MNPeHJwBZi/cdFAxjfYoE
         ZJgDjv1y/rYoVKxzIFJUMtuJ5wiJHbajryYWvdAicf5Nvi/l3cmaYL53kZvUvMlxLLG6
         3RKDn2um8DLWk5cb5MoJdILJ0nu7lXUM9nCa+3X3tfMRCoPEUuGYVOw1XOrT8guCWgDN
         ky8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=/5oxsQN0WjeacNPZbyuhLqugJ5ZZuNAGf5ny17r2BuM=;
        b=xlKdvzn8cLVSgENvsyQYP4k07ZpYruZGoVm3gaZc6iLwNa58fQtJEQ57Jo5ndMvW89
         lkuc7GzAwsJD3ek6ZJUA8wWgjb9yf/x0QWAq1go5ndYuOwmEvYOoRFjADy/2pRiJbLF8
         AqtCmg4wcUgqBoh3oo7MPdUzAB9XtDQ1Rvf83El9bOEkUT971Ot4xbc9QWIU2CPnmWsN
         wihhzkeDm8621kj8eVJJWdx48/2n/DSdRd9laxHt0Dkm5T5nzLjZ1MNLqgJ6n4Y+V24f
         CcQJerwLJburMBosl6kBYAA1DHrsqZMz8vrolI5EFEotacixSPc1bILHmIK0Ysbcj+PW
         TSbg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lFDOhEqV;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/5oxsQN0WjeacNPZbyuhLqugJ5ZZuNAGf5ny17r2BuM=;
        b=FvsUv1YTFcHrTyR7LhuHfLPs73Ro2Ej/XJ+QLwtvRO2gYQHgSgeFzMEM80kKCsmgPT
         MVsGByxDRO2G5ToRrH6YCnY7e6vcmFfKuoppaRTYsgbE4O26WCICIPgE3zZFuYhJpqJI
         NApGVjLK1grCRGYAZwv9nmzQExzfoWw0FdSRsG/gITMhdTo/1lhR2/pAGdwLMSpJCuZt
         oHYIa8Jm1Xe6N7Wl4d71A2dtQeisfZWEegk7mFbvGLmuo7y3jPzFrDxcCkIwteOUMUB+
         lqfGLXPHRngGOg+lhOfEdWXm6rUCg1RkfMqdhnlsu4ELZOGgimYzAdmoWvJfG4KBmFsD
         I5XA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/5oxsQN0WjeacNPZbyuhLqugJ5ZZuNAGf5ny17r2BuM=;
        b=POdpChYLMyeIS2LDMUm/Ca6/utp+7km3zYVijg+ZAK+bht7gqnR5tW5yzb5BpKhdKk
         VEt93jumjF5yCzLoln2Ky1hefPkdg/Cx0wG+oL1dfM/XS5I6mlaXEtDrFQBdwCKIvmKB
         6JItxkDTGVzdk+cto3cCH+Ew/c1zuerYersi+h8/AuMsENvM96ZKx/SCbcspCb/+wmkx
         aZOR59qffsvZ7HDkcmDd1abnEqiUuDV/lpA07fvgMm7bLFoo84095/p+oSUCfVToslZu
         85fwkPzg9uSncNgI710vP4Sd6VKP0QsRrtsxwT2aSZgBvFL4NQS5ze5l09oKiixwsQSp
         PgIA==
X-Gm-Message-State: APjAAAUd51Tg4XZuIu4qMv72X8Gd0mt9IdASckINpeD4eoxEaqRi5k0A
	jmyx47tZcLw+p+doai73AVM=
X-Google-Smtp-Source: APXvYqx851ijQMHfKJdaDRezIIMU1JdD1ZUhpgQyW7EWfjaAxuDnDERUw7n2+rXvCWxrKCvrZ1y9EQ==
X-Received: by 2002:ac8:4117:: with SMTP id q23mr10347936qtl.66.1573467469060;
        Mon, 11 Nov 2019 02:17:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:6289:: with SMTP id w131ls1769624qkb.15.gmail; Mon, 11
 Nov 2019 02:17:48 -0800 (PST)
X-Received: by 2002:a37:ba44:: with SMTP id k65mr9916179qkf.169.1573467468607;
        Mon, 11 Nov 2019 02:17:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573467468; cv=none;
        d=google.com; s=arc-20160816;
        b=i+nKxblnVjFehnVXc+Ww80Wd3a8+z+XGI3Z7sQ/FnOuEwlZtLxg84QRAWJ3AVBuh9G
         XVl/qi0X7ABtLvwsNrMUJ6+rDIwRJhNwz5Fzzo0h9kwHiDlp0CFjcuWtZ9GsnXuspwsI
         jrI4J+lD4j11SViF3WhZ5rAheKX9Kur8CNH4l/TgXUo6wAmZGWSF63YiQikFEdmQ/P+A
         +9LQH3owXroHWGqr+vCEWnjPb380hgNe1k32I6PRFCgU80XrFbe/CR7r9CNTydl/REDO
         74yvbj3G3Rh9F7EhbDZs98jFiWhPTWBcRmrrevwff2yvVLuzAbCCXImPi7u0aeCtOTAL
         I7bw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0DS5VW8HLST3ocKeDeJ9QZgQRHqn3pgbndgTPCNayrE=;
        b=oDUphmzWg2OEj7LygaCL1tPTStrQF6lvnnop/ajd2eVGn7KFVlq8Bii3NqNz7DS75k
         ZkJA7nirtuEw5pk515FlPJGtblYJ05Zhux7nCX1da7ROyFb0S9sN9PN0CSeVRB6G4LsY
         PdtBb+oNouESrdZUzrQ2y8zkWZLmhM78P4ba+iDYtGUSdJuJniZObPVma1fZIDRtkKNY
         aEFdjbmChMBC+C8S1znn7XaRYbOeaOjeRVYMJcRGCg4LSZXA/U5XjOWrGNeezVoYHrvt
         zjY3NcQ5fW9kOdVYvm6xseoZVnW4lDPbVkvUdRy1kJbSZkPv7hAMAx5LDjUTUUjC5wOq
         gCqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lFDOhEqV;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id y41si1214483qtb.5.2019.11.11.02.17.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Nov 2019 02:17:48 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id m16so10652906qki.11
        for <kasan-dev@googlegroups.com>; Mon, 11 Nov 2019 02:17:48 -0800 (PST)
X-Received: by 2002:a05:620a:1127:: with SMTP id p7mr5628740qkk.250.1573467467767;
 Mon, 11 Nov 2019 02:17:47 -0800 (PST)
MIME-Version: 1.0
References: <20191104020519.27988-1-walter-zh.wu@mediatek.com>
 <34bf9c08-d2f2-a6c6-1dbe-29b1456d8284@virtuozzo.com> <1573456464.20611.45.camel@mtksdccf07>
 <757f0296-7fa0-0e5e-8490-3eca52da41ad@virtuozzo.com> <1573467150.20611.57.camel@mtksdccf07>
In-Reply-To: <1573467150.20611.57.camel@mtksdccf07>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 Nov 2019 11:17:35 +0100
Message-ID: <CACT4Y+bxWCF0WCkVxi+Qq3pztAXf2g-eBG5oexmQsQ65xrmiRw@mail.gmail.com>
Subject: Re: [PATCH v3 1/2] kasan: detect negative size in memory operation function
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lFDOhEqV;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742
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

On Mon, Nov 11, 2019 at 11:12 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > On 11/11/19 10:14 AM, Walter Wu wrote:
> > > On Sat, 2019-11-09 at 01:31 +0300, Andrey Ryabinin wrote:
> > >>
> > >> On 11/4/19 5:05 AM, Walter Wu wrote:
> > >>
> > >>>
> > >>> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > >>> index 6814d6d6a023..4ff67e2fd2db 100644
> > >>> --- a/mm/kasan/common.c
> > >>> +++ b/mm/kasan/common.c
> > >>> @@ -99,10 +99,14 @@ bool __kasan_check_write(const volatile void *p, unsigned int size)
> > >>>  }
> > >>>  EXPORT_SYMBOL(__kasan_check_write);
> > >>>
> > >>> +extern bool report_enabled(void);
> > >>> +
> > >>>  #undef memset
> > >>>  void *memset(void *addr, int c, size_t len)
> > >>>  {
> > >>> - check_memory_region((unsigned long)addr, len, true, _RET_IP_);
> > >>> + if (report_enabled() &&
> > >>> +     !check_memory_region((unsigned long)addr, len, true, _RET_IP_))
> > >>> +         return NULL;
> > >>>
> > >>>   return __memset(addr, c, len);
> > >>>  }
> > >>> @@ -110,8 +114,10 @@ void *memset(void *addr, int c, size_t len)
> > >>>  #undef memmove
> > >>>  void *memmove(void *dest, const void *src, size_t len)
> > >>>  {
> > >>> - check_memory_region((unsigned long)src, len, false, _RET_IP_);
> > >>> - check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> > >>> + if (report_enabled() &&
> > >>> +    (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> > >>> +     !check_memory_region((unsigned long)dest, len, true, _RET_IP_)))
> > >>> +         return NULL;
> > >>>
> > >>>   return __memmove(dest, src, len);
> > >>>  }
> > >>> @@ -119,8 +125,10 @@ void *memmove(void *dest, const void *src, size_t len)
> > >>>  #undef memcpy
> > >>>  void *memcpy(void *dest, const void *src, size_t len)
> > >>>  {
> > >>> - check_memory_region((unsigned long)src, len, false, _RET_IP_);
> > >>> - check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> > >>> + if (report_enabled() &&
> > >>
> > >>             report_enabled() checks seems to be useless.
> > >>
> > >
> > > Hi Andrey,
> > >
> > > If it doesn't have report_enable(), then it will have below the error.
> > > We think it should be x86 shadow memory is invalid value before KASAN
> > > initialized, it will have some misjudgments to do directly return when
> > > it detects invalid shadow value in memset()/memcpy()/memmove(). So we
> > > add report_enable() to avoid this happening. but we should only use the
> > > condition "current->kasan_depth == 0" to determine if KASAN is
> > > initialized. And we try it is pass at x86.
> > >
> >
> > Ok, I see. It just means that check_memory_region() return incorrect result in early stages of boot.
> > So, the right way to deal with this would be making kasan_report() to return bool ("false" if no report and "true" if reported)
> > and propagate this return value up to check_memory_region().
> >
> This changes in v4.
>
> >
> > >>> diff --git a/mm/kasan/generic_report.c b/mm/kasan/generic_report.c
> > >>> index 36c645939bc9..52a92c7db697 100644
> > >>> --- a/mm/kasan/generic_report.c
> > >>> +++ b/mm/kasan/generic_report.c
> > >>> @@ -107,6 +107,24 @@ static const char *get_wild_bug_type(struct kasan_access_info *info)
> > >>>
> > >>>  const char *get_bug_type(struct kasan_access_info *info)
> > >>>  {
> > >>> + /*
> > >>> +  * If access_size is negative numbers, then it has three reasons
> > >>> +  * to be defined as heap-out-of-bounds bug type.
> > >>> +  * 1) Casting negative numbers to size_t would indeed turn up as
> > >>> +  *    a large size_t and its value will be larger than ULONG_MAX/2,
> > >>> +  *    so that this can qualify as out-of-bounds.
> > >>> +  * 2) If KASAN has new bug type and user-space passes negative size,
> > >>> +  *    then there are duplicate reports. So don't produce new bug type
> > >>> +  *    in order to prevent duplicate reports by some systems
> > >>> +  *    (e.g. syzbot) to report the same bug twice.
> > >>> +  * 3) When size is negative numbers, it may be passed from user-space.
> > >>> +  *    So we always print heap-out-of-bounds in order to prevent that
> > >>> +  *    kernel-space and user-space have the same bug but have duplicate
> > >>> +  *    reports.
> > >>> +  */
> > >>
> > >> Completely fail to understand 2) and 3). 2) talks something about *NOT* producing new bug
> > >> type, but at the same time you code actually does that.
> > >> 3) says something about user-space which have nothing to do with kasan.
> > >>
> > > about 2)
> > > We originally think the heap-out-of-bounds is similar to
> > > heap-buffer-overflow, maybe we should change the bug type to
> > > heap-buffer-overflow.
> >
> > There is no "heap-buffer-overflow".
> >
> If I remember correctly, "heap-buffer-overflow" is one of existing bug
> type in user-space? Or you want to expect to see an existing bug type in
> kernel space?

Existing bug in KASAN.
KASAN and ASAN bugs will never match regardless of what we do. They
are simply in completely different code. So aligning titles between
kernel and userspace will not lead to any better deduplication.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbxWCF0WCkVxi%2BQq3pztAXf2g-eBG5oexmQsQ65xrmiRw%40mail.gmail.com.
