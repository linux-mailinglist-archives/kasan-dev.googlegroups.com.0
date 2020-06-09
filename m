Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFF77X3AKGQEHBDYJHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 220701F379F
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Jun 2020 12:08:21 +0200 (CEST)
Received: by mail-ot1-x338.google.com with SMTP id w21sf8544207oti.16
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jun 2020 03:08:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591697300; cv=pass;
        d=google.com; s=arc-20160816;
        b=nGjOVS732bZimfMRldCiLOtxkuOSNuHXEjeS6UBldm/i0IVQhZ0oHrqzykghBEWPQD
         vbzlWynE9ACT7FjMxRxQF/LEl1WeZZziIV3uVEu3M19Dft4TroosrXL3x3r1yf2QaBV8
         ENA6cAlKdRP3uMiG4tRn++FvzboqbICedzSIh2/0HRNsAZ+Hr6wsay2YrBaD/QMMIKKH
         PLHvUy6HJEgXycK3RIaUTGqsVluWjnIgZXKuba4Mx1uJeHl1KITYarQyTe+ka/SAIWvn
         /3voFmZgfEh/umAIv38iBFzXhioc8X++q/bxm33ppYIffUTnNYPTE6mW6hwLF8Fed89U
         5+sA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+Ti/NaYJh6RS5V4J3twfNvMEHevZoLVLOfoCrOacGwM=;
        b=AaP6vYE+n0bdmd+dVCVIoZSLkGvixTZvLDsLe3WinA6XCJl4nlxsmHpua2Y7BRzGJa
         mU6zBLu1dqaNnd5dLw4tIh9SJiG+pYZ4MOYSmlA0P/uKkQaYShSgRXj8oMBfGzKbLXbT
         ECGwls3esTxI2YZSMrAmOkUYulSMdvYRW6FqzP7addCqrbuUYyIrLU6fVxkiR1pADxYE
         I91uPhxZzAxK+FNO1XwWivh9fNz7xYxAil9ehDB28tFmilrDGc8tRdqpct40hlpN5bsU
         ZU5K/Sdapl8WeQs59nzajEK7ksBNeqHcoTVVSk4FYWRYEXEZO60HHV9QS9bGgG2dfR2P
         B04g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bFJ3XuYP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+Ti/NaYJh6RS5V4J3twfNvMEHevZoLVLOfoCrOacGwM=;
        b=eLrz1e06nRs/awl6mtivRcEyD+YYByS0/ynCXPsWxe+Bcma7mituerrypt2+MYB+ri
         QbbEutxV0J3RyMGHQEni994DgrpyYumjOG+HeyN8BkTTj9Q8fKf/fi6+QUVHd+KXPSpG
         CJw63koesxAQ15gwahjCblZkIqMYNquX4YsSXMYKNyH87uXv2BkMXpcRpZXO2Ajp9IJ0
         MrutEnKkFiyncju91jLY4UzsWewxrgjiNQJv2Lh4yqnSRyCKcTbZFeYybe9zLdGQh50T
         ceJeiYssrnYHJdoMVbRgzi9QT0kTIgldyikJHqRatWACpRAJVEGdRtG+BXCVbqbqErP8
         TJ9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+Ti/NaYJh6RS5V4J3twfNvMEHevZoLVLOfoCrOacGwM=;
        b=Urx/6m9PUNAXvkEkUXyA8ZbTS+JAP2iTwpkSUZpmc/FLNSKBE8WL2ZwrTW6A+Y4JeQ
         MePLfZ6E4ZunKH8DF1XWrkGf/cyzLSX6wqvRKmb72KSQCGV1vPS0fH7zJMWNeiooIaJR
         FlGbbjBCCWa0ATU7wEwxhco0AIDeXlukdyUTFjAhMueWnOi6/ySs7ndjvdKcVgmI/Nbh
         DaquFLt6WGPQfrfPbqZCtBg+roz9ovFqBsmLDqCN8Ti3AHdmBqQddSHjusenk0sUjqRX
         v8nSV2eWKrrnUzA6QaflRxRD/RFF4EAVNv4nye49utM1oPfElut8qG1CVsQ/25yj7fJv
         lk3g==
X-Gm-Message-State: AOAM532u7ppo2fRceL7I7rbLPlqaN64B2+NpDYgbuzxlfy3smos3AnWt
	M1lqvB7f6i9lJasTp3ZlIb8=
X-Google-Smtp-Source: ABdhPJyIhDGbQ52Qqv2D/T1jWiUXeEAYaqjw+j8EnBkpH6Yx0kfwW/kz4RXOub/mmQpslflcFLsDrw==
X-Received: by 2002:a9d:d6e:: with SMTP id 101mr20786662oti.166.1591697300090;
        Tue, 09 Jun 2020 03:08:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:524f:: with SMTP id g76ls3777376oib.6.gmail; Tue, 09 Jun
 2020 03:08:19 -0700 (PDT)
X-Received: by 2002:aca:528a:: with SMTP id g132mr2679314oib.113.1591697299793;
        Tue, 09 Jun 2020 03:08:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591697299; cv=none;
        d=google.com; s=arc-20160816;
        b=PtXy7HA1vvqCr51A/3vqcBzzAeHL5bEplDAr3X3XCoH9t+on93XidRu3HIKgpta7/k
         +Fhhnz6KVHhjhQlQ0rtUiIYNtirYPNaRy56JsON56+i/vF7NmTPJoIbaqjF7c8gV2bry
         vGFuKgu1LOO90l22XUNxzDQcMHGIchwQi9Wjil1DvrjcoEpm9LkUP1byb5N6FDA9SgzL
         gG5w1DkfUZPuqA0RtBf5uy5/i/Ir4G5pm6o6BeX7ygSMuGaZ4tH+dxjV5kQkljNGy2VY
         CC8zZ0eztGVkK8ZzSslkb5rl3iVwbuS/PVm4YfNVrLM9XzZIWolD01ns3reVTrbQQXt+
         3E5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ia9MK8JMIBc5UmYkXQAIHLh3RviWvfVPcjvoPpOSV+s=;
        b=DbWl0SZltEmtT1D6JWPC+MKbnJLKs8z1MYxh+ByRoSv9mkk2j+TCHbHPUO2hZDaDhp
         ohIPB7TD28huq0RklgSn3sYPzAvwcn8Puk/V61a8Aun7NPFS87HKeesJLHvpXOMQMrb/
         WodV5a1He/qn/bEIyVdPEXzWbPkSwSwVb4ZzxJ1Vvov4VxXLKa4zbMFbv0jp4pLmzixv
         YqXb3tcx7mHokzIi0S3jaqoUDNPkmXAJUk6bxlw8+uV0370G1a8xIM9cbi9CA2Ve7uIZ
         te74sY531aChok+6zeYZ0X2iBPvbhYUrpKqmvptqjpz+NjbYivrNx7oeZWqfURq0NQIp
         DgRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bFJ3XuYP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x229.google.com (mail-oi1-x229.google.com. [2607:f8b0:4864:20::229])
        by gmr-mx.google.com with ESMTPS id e23si830166oti.4.2020.06.09.03.08.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Jun 2020 03:08:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) client-ip=2607:f8b0:4864:20::229;
Received: by mail-oi1-x229.google.com with SMTP id i74so18208756oib.0
        for <kasan-dev@googlegroups.com>; Tue, 09 Jun 2020 03:08:19 -0700 (PDT)
X-Received: by 2002:aca:ebc5:: with SMTP id j188mr2766132oih.70.1591697299326;
 Tue, 09 Jun 2020 03:08:19 -0700 (PDT)
MIME-Version: 1.0
References: <20200609074834.215975-1-elver@google.com> <20200609095031.GY8462@tucnak>
In-Reply-To: <20200609095031.GY8462@tucnak>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 9 Jun 2020 12:08:07 +0200
Message-ID: <CANpmjNN8bokP95tkHV_HnmFo8w3OksMHw4DDFJLh_5gU4g0m0Q@mail.gmail.com>
Subject: Re: [PATCH v2] tsan: Add optional support for distinguishing volatiles
To: Jakub Jelinek <jakub@redhat.com>
Cc: GCC Patches <gcc-patches@gcc.gnu.org>, =?UTF-8?Q?Martin_Li=C5=A1ka?= <mliska@suse.cz>, 
	kasan-dev <kasan-dev@googlegroups.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvuykov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=bFJ3XuYP;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Just wanted to change this one, and noticed this

> > +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE16, "__tsan_volatile_write16",
> > +                   BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)

is precisely 80 characters. So if I read the style guide right, it's
<= 80 chars (and not < 80 chars), right?

> This last entry is already too long (line limit 80 chars), so should be
> wrapped like:
> DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE16,
>                       "__tsan_volatile_write16", BT_FN_VOID_PTR,
>                       ATTR_NOTHROW_LEAF_LIST)
> instead.

So I think it can stay.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN8bokP95tkHV_HnmFo8w3OksMHw4DDFJLh_5gU4g0m0Q%40mail.gmail.com.
