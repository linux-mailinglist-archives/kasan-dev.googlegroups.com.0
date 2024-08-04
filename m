Return-Path: <kasan-dev+bncBC5OTC6XTQGRBFXTXO2QMGQEIS3NUUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0881A946C15
	for <lists+kasan-dev@lfdr.de>; Sun,  4 Aug 2024 05:46:32 +0200 (CEST)
Received: by mail-oi1-x23b.google.com with SMTP id 5614622812f47-3db1d480843sf9148887b6e.2
        for <lists+kasan-dev@lfdr.de>; Sat, 03 Aug 2024 20:46:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722743190; cv=pass;
        d=google.com; s=arc-20160816;
        b=jjFQAYSnC29/uJPrX3rCqE0jrGS6rUIXuAKG0Hy0wNL80fkIYMfS3rZCvEIaoCqbgl
         CQ+0o/8UtDVC6SQYbVa5rcbZ1ed/1bipE81mYct6Q6ohK3l6tBCQC8TCCQqp4YT+KtEV
         wrr5PIpjxGDy91wFgVYi3yMdIWKgMKe9jfgCIbLOrIsQzyXMR0GwPame4marEFdFZOUC
         IJL8F6C+I45/EHJOZABW/d9ZziwbxGUJt42hPwAQTDPLGEaWE9SLPSUJfeHh71ctHUYj
         CIEiHUAIl/hzWbLMmDCFpTYVvnskwTsNdgxcWvODiWNK7YBYhvKPUfXZ+pHOoqLB83j6
         OanA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from:sender
         :dkim-signature:dkim-signature;
        bh=IwB5/6+q9iNNzvs7c+w3roiP2Paz0Gx91Jm8kSiLwF8=;
        fh=W2b73LFf13aEEnM88J7Qk/D9fAUd21xV6BsVSHvmniI=;
        b=lKH0/HJ81RpJxyPdSXODmxHmQF6+/57VD7GE5o9WNFywdkWm8hLY4rbcBpwwY8cNrb
         xPaJzYqptGcp1mEUSMDetuPQeA52/xW0lSqusqn3olCs5vYl9msg6HTWRIYMNyaY5hhx
         +Oue/UCtI5Y/PgrFFP7lScqkvPGZYY53utvP/+tUlc8LxeMyV+HDYh2TffOmtLzkN+Xb
         gaLAjHZhR9DrIxxmUo88C7mevieiWUn8fY5hiGEOOFWg1JUtuVrBC311sOHjK8290imA
         uqQd+qmar9FKgQKVFJuNoio5xMPsCO28ywY8ZdroWEHKHjcSH3tEvOjcrlLlqJ6CP/Kr
         foig==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=T+7UIY1G;
       spf=pass (google.com: domain of qiwuchen55@gmail.com designates 2607:f8b0:4864:20::1130 as permitted sender) smtp.mailfrom=qiwuchen55@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722743190; x=1723347990; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=IwB5/6+q9iNNzvs7c+w3roiP2Paz0Gx91Jm8kSiLwF8=;
        b=P6SmyItInbNoNQj1oNkPlur+JpcOIcuYWAhi5QEtI/85JWGVRMwhrteqTJE4cmRCnv
         A37ipHOfDggu1kWMUszocDo+UTgHC/ew1sgaq5nknWjAt6Q3v1nzKUV5UsAHJ/geLztS
         rHAA6S13XuZTQQJZmEpD69+MoOvHos3aI0hPjvd6OUXzwV8eDgKvnnR6oMwJfNDb47rn
         RNCDc1KH8INGyH45hpTnmU81wrhRfop52CDhtzIEMFSM0Ha1LjzYNZT+yJY0vWoZxuKq
         q12Y0rHRvO5CJqzsXA9RGF3cpEU5S9kCY6QRoG41g/cSZycfRXiva63XSlUVE4G7LWCA
         NIHg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1722743190; x=1723347990; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=IwB5/6+q9iNNzvs7c+w3roiP2Paz0Gx91Jm8kSiLwF8=;
        b=CxJ/zPAP6MQCpVioiwNmkY0WyeRXabyNliSYDpQrdd4TiF+jWqxJmq6u3WgR8ArIrZ
         maWvp4zdEhdwOj5Y4KrOPcfJVtSPwZF5XW9maD9W/RVm6PX8/GvLbQ1EXt1i+Yqi5gz7
         gBXo0Esp2VR6K9ws/d6Bp0rBQ7Kymsrn7ywR63J9IZFHukXNnkZXzAv2fykDwmXHoAG2
         ctiprOxv1UoJT5EnucoWQFfjJDXJ7/gXmgCjxr6ONAuGErQ8A1pGmSdG/k/b9vHr295M
         MUn8af0+cr1fVb7oTj2JYi1ipKiz7aWHRv06LIY+NZp1wd2X7ODRAM26b0JtmhKXLqNI
         +KPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722743190; x=1723347990;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=IwB5/6+q9iNNzvs7c+w3roiP2Paz0Gx91Jm8kSiLwF8=;
        b=o5ALILlo1+H10q4WiNNZxKriv1gu8h6znRWpP5xjNyFN6aZkNOgkgkmfgXiWhbDj+w
         WFPkio20phheO4NWeO0WLYPHzlX2VXU/4vl/oO5+ay54ymlTBupcr6B+YoyxJDdPvsXz
         v9NW3zF9gnN3U47rU6XuFAH2rKuuRDBoWevlUZy8UHGsEsgaj95Ef2hGkL/IppmZSxbn
         Yg5c5EXgHOVNwmQ70ht8+S3cs+nVUD+MaOAgpvZJXWL7JNAwPBBFQzKlun+NDxmYcyd9
         tF6a9dlbd/5C3uf9szqaCnDGvGwSq7pil29mTUwrt1jJ/kzA3xT6fHWtub5sYSiSiugu
         D7eA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWmqdkPO000H0BFrYRaHymy50KM6r2PPHG2kJNnujpw/f1seLgbRQgS7DUd9/Fli8G9Qz5D8jneYcAgAn8u3Jgw6JPDeD3J+w==
X-Gm-Message-State: AOJu0YwsP69shYuXF75sE2m4aq5VaYA7LwMScWA03wDmmqW42kQQY7xy
	yTLopBAxbN9vgWrwO5/6P1MzoyvxrVj92fj6cd2Fzk6vPRfrMPMt
X-Google-Smtp-Source: AGHT+IGEkMykC1g62qcSEeVkaHSKetrs/FGqNW8tdOjDR4CWNYGUFXK5I4Ldjmmx1Kcwl53RAUzG7w==
X-Received: by 2002:a05:6870:c1c9:b0:254:b5b9:3552 with SMTP id 586e51a60fabf-26891e8ce74mr8292289fac.33.1722743190217;
        Sat, 03 Aug 2024 20:46:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:44c9:b0:259:f021:752d with SMTP id
 586e51a60fabf-268adaac5f1ls1785748fac.0.-pod-prod-07-us; Sat, 03 Aug 2024
 20:46:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXxcmhoNUpsS890nU9c4epODR5iMuO9pbOMRITauU5jPqfD6EEcQdWH+823sMIXj6xKnK95m/vkCG/jD2itpzL9suldFmTxDzDclw==
X-Received: by 2002:a05:6808:130f:b0:3db:251b:c16 with SMTP id 5614622812f47-3db558397b9mr9286065b6e.42.1722743189550;
        Sat, 03 Aug 2024 20:46:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722743189; cv=none;
        d=google.com; s=arc-20160816;
        b=Jzc28HGIlCi8pWy85FHnngPG+upJl0eQvkr7H0stPkEDxUik77xnTF/fd8FP2qpRIN
         1xp6BbOfHRafIM6udpKcObkjM/Wid8DpN54j/mRs9oKlChUWpBJF6GgjkHJoQOMcpc03
         z2eOV/HQPWguBY1znlOo674xFbWtCSnRy6DzPV2gSG42eSgtPHsfhS4cfOAjEr5tWJuJ
         6fI7IjhosaFQ1/u5z6mFODOLZEY8BqhwqvU5A/GlNTou8IexVZeaBFXeeZNkZ2J46+ot
         Y1hSOJK0emzjlxq65yPWgQLkcJFDwEaEo3u1MCTMj9LSULnU7c+NWYNPXwU67QnwW2Tf
         aYng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:dkim-signature;
        bh=aKeNnkpQpwJqSEwqqAlpkjAwyz2FvuskXOfxkNi23iw=;
        fh=Xcm++LD+UlPT/8lSMhu5ubBgqXqRCFLVDeS7GDKg3rI=;
        b=FwAlI9unlyQu+NMgMV25ys9EWb7ST6paLrLh2UtZdkq8JHh3GWs8GP9oqdxH/g2gGp
         SiaQ0IoyZ+j7emaU38b1tmB04tnklGv7Rf0c0EZpu1Va70OULebG2V/AcI7JbnxJMlYu
         fs71PlRo3tB3N1xNQxIF78BQIxCo6AnYy0SvailSYK5+DZ4LnDN0lPH5MGV4mG6l36cH
         uCmfMaaeNk7ye8abDhFsuBXLyT6Z5zMnblBZIncNlsi6PAwm9NlSmPWQbQMLa8IEjjpg
         TbDlchp03WSh9h+43QWQYbtgB131+PMt1Bmp1l2gNPgVJwnz/QZ0G2q/eNTstomd63QI
         7ECQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=T+7UIY1G;
       spf=pass (google.com: domain of qiwuchen55@gmail.com designates 2607:f8b0:4864:20::1130 as permitted sender) smtp.mailfrom=qiwuchen55@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yw1-x1130.google.com (mail-yw1-x1130.google.com. [2607:f8b0:4864:20::1130])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3db5627de3bsi255591b6e.0.2024.08.03.20.46.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 03 Aug 2024 20:46:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of qiwuchen55@gmail.com designates 2607:f8b0:4864:20::1130 as permitted sender) client-ip=2607:f8b0:4864:20::1130;
Received: by mail-yw1-x1130.google.com with SMTP id 00721157ae682-64b417e1511so79039617b3.3
        for <kasan-dev@googlegroups.com>; Sat, 03 Aug 2024 20:46:29 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVSbWTuP9QwrCJPgFHB3TLSNqri4rjpGC53+K6zoLQR3nJT7M1kBk9JBUuRr0BF6feOL4KXIIJisMxRZnuc8VXSwIs236MSxYh0CA==
X-Received: by 2002:a0d:ed83:0:b0:664:a26e:5ab2 with SMTP id 00721157ae682-68960491085mr85910277b3.11.1722743188892;
        Sat, 03 Aug 2024 20:46:28 -0700 (PDT)
Received: from localhost ([183.226.244.186])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7106ece3b99sm3499202b3a.98.2024.08.03.20.46.27
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 03 Aug 2024 20:46:28 -0700 (PDT)
From: chenqiwu <qiwuchen55@gmail.com>
Date: Sun, 4 Aug 2024 11:46:07 +0800
To: Marco Elver <elver@google.com>
Cc: Qiwu Chen <qiwuchen55@gmail.com>, glider@google.com, dvyukov@google.com,
	akpm@linux-foundation.org, kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: Re: [PATCH] mm: kfence: print the age time for alloacted objectes to
 trace memleak
Message-ID: <20240804034607.GA11291@rlk>
References: <20240803133608.2124-1-chenqiwu@xiaomi.com>
 <CANpmjNNf8n=x+TnsSQ=kDMpDmmFevYdLrB2R0WMtZiirAUX=JA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNf8n=x+TnsSQ=kDMpDmmFevYdLrB2R0WMtZiirAUX=JA@mail.gmail.com>
X-Original-Sender: qiwuchen55@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=T+7UIY1G;       spf=pass
 (google.com: domain of qiwuchen55@gmail.com designates 2607:f8b0:4864:20::1130
 as permitted sender) smtp.mailfrom=qiwuchen55@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Sat, Aug 03, 2024 at 04:51:45PM +0200, Marco Elver wrote:
> 
> typo: convenience
> 
> What do you mean by "object leak"?
> 
It means an allocated object of slab memory which is considered orphan,
perhaps it's more clear to say "For a convenience of tracing memory leaks by kfence",
what do you think?
> From what I see the additional info is only printed on out-of-bounds access.
> 
> Or do you mean when you inspect /sys/kernel/debug/kfence/objects? If
> so, that information would be useful in the commit message.
>
The extra elapsed time of current allocated object would be useful to figure out memory
leaks when inspect /sys/kernel/debug/kfence/objects.
> However, to detect leaks there are better tools than KFENCE. Have you
> tried KMEMLEAK? KFENCE is really not a good choice to manually look
> for old objects, which themselves are sampled, to find leaks.
> Have you been able to successfully debug a leak this way?
> 
The kmemleak tool has limitations and drawbacks which cannot be used in productive environment
directly. KFENCE is a good choice to find leaks in productive environment.
> > alloacted objectes in kfence_print_stack().
> 
> typo: allocated objects
> 
Thank's for your comment.
> 
> In principle, the additonal info is convenient, but I'd like to
> generalize if possible.
> 
> > +               u64 interval_nsec = local_clock() - meta->alloc_track.ts_nsec;
> > +               unsigned long rem_interval_nsec = do_div(interval_nsec, NSEC_PER_SEC);
> > +
> > +               seq_con_printf(seq, "%s by task %d on cpu %d at %lu.%06lus (age: %lu.%06lus):\n",
> 
> I've found myself trying to figure out the elapsed time since the
> allocation or free, based on the current timestamp.
> 
> So something that would be more helpful is if you just change the
> printed line for all alloc and free stack infos to say something like:
> 
>     seq_con_printf(seq, "%s by task %d on cpu %d at %lu.%06lus
> (%lu.%06lus ago):\n",
> 
> So rather than saying this info is the "age", we just say the elapsed
> time. That generalizes this bit of info, and it'll be available for
> both alloc and free stacks.
> 
> Does that work for you?
> 
It does not work for me actually, since it's unintuitive to figure out memory leaks
by the elapsed time of allocated stacks when inspect /sys/kernel/debug/kfence/objects.
It's unnecessary to print the elapsed time of allocated stacks for the objects in KFENCE_OBJECT_FREED
state. For the elapsed time of free stacks, it seems no available scenarion currently.
BTW, The change from "age" to "ago" is okay to me!
> >                        show_alloc ? "allocated" : "freed", track->pid,
> > -                      track->cpu, (unsigned long)ts_sec, rem_nsec / 1000);
> > +                      track->cpu, (unsigned long)ts_sec, rem_nsec / 1000,
> > +                          (unsigned long)interval_nsec, rem_interval_nsec / 1000);
> > +       } else
> 
> Add braces {} even though it's a single statement - it spans several
> lines and the above is also {}-enclosed, so it looks balanced.
> 
> But if you follow my suggestion, you won't have the else branch anymore.
> 
I'm not opposed to convert a single statement, but it will have an effort to find leaks.
This change will be helpful to find leaks easier by grep "ago" keyword when inspect /sys/kernel/debug/kfence/objects.

Thanks
Qiwu

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240804034607.GA11291%40rlk.
