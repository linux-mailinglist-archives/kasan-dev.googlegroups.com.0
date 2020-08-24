Return-Path: <kasan-dev+bncBC7OBJGL2MHBBR6SR35AKGQEX3HORHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id BF76724FCF2
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Aug 2020 13:49:28 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id r15sf218308pjo.9
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Aug 2020 04:49:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598269767; cv=pass;
        d=google.com; s=arc-20160816;
        b=OV2DwLgnt2uO20LRlXY9kxtNHOsMP/fU4fTEWmHPBmBy5vKxd4r5+sqKalzn36zLRO
         x7hHnd4IGuMLL57DmFCp3n4NXw0O4lzwuX8EByM9elWe5S/TQiRZpoYXJU2/Mpt54/e6
         OqQhyTpo4uEVmJBfyn8ECGo4yBV1OgzVsVIqotnkGtXElqwa8qLsp0n6l90Z2wvUhiqr
         ZBj5X+aXkulU6vjt0WX1y8GGvTd2GRQU9KvZmqFGKjUV/9G4VnOxswY8FxN0TeLk5Ylk
         MGMeZJJAatz81zzKGhoMxZSRLcelQeR+KgAC5/84z2/dUKh5vU/I52RoENaV8Cq0T4r/
         vNeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=HpWNevB92BqXce3eiTZbxN+iIUsKOakdwRC8DddgmN0=;
        b=l76WAr6r614WvKYFrzAwEyRQw/uMiQXC7TC1z0pPyimLjePoieVWur4UoI1Rdxs6Gu
         dGLEpewf49jRtNzi225tNODuEjluDZ1yKt3zGPC1VbXeXgYrc5PqB9FZKV/QHZHeQ7/z
         Ti5KdEJPKF5rdtFYyueRE6N+SmaGs/p/lYPyrN5C1LcEdD3j8cMpGP6Kw70VdvojCEGr
         ScFjaC795X3ayntnAMaL1QjPtiHFGeY2QxKqn5df12Uy8DL7O0madq6BNWGpSKqBVAJr
         EexacKFXqF2U9hflTZgDJVdtptsrO2Qp+Q/vHo+hFCTGeUPKRFvj7Ujl0ra43KxW3eAC
         qk8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ifu4mAhc;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HpWNevB92BqXce3eiTZbxN+iIUsKOakdwRC8DddgmN0=;
        b=J1IlP0JjlhfSmG4moaYfZ6jHutASe3QVuDqbVIbuhe4dqVK7HbHziNfKnhbHKMaj1J
         GPhy6YgDkYO/gtKpmljYurE/fp4ru8PbP2OGkqt+jSFGipn8uw7G7sGzEfoBxZht/CS5
         4pzt2DXl47gXEfjjUIdoLiTU3qMDdvHzudZv1FspiWBHcKd9/u+2KLkUqD1JfVUKLBLi
         Ybb4EpkLZk6UgorP+YWsJ94jyaR2Xm3/Ty31wmZhhjX5QTA2xwQowUOjTSNYAXSuK2yI
         W9AcV+nuSw7bRX07EStbCcVu1XtagKs2zBlPNYEMjq5sDlCpkHrjCcIUg2J089D7J14S
         4Z2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HpWNevB92BqXce3eiTZbxN+iIUsKOakdwRC8DddgmN0=;
        b=ImAVlBAhNyaRYpt06SYR3yuPBQX5/GtJfYme9fQWUXu5PYaD7rsknaBLMrfCc7qgz0
         Hw1WrODi8NlLMB67ilKQaviESCDlMiiHGMevuAifR9yVMKwqNB3MsWP3sIwrM3HGZala
         052zvh2SV8ZdOKhfSEuHCd9hMl/w+1bTVaM//KHXOj/87iI4Pbn8ePTE8ICdtQL5d5UY
         /evW733nTkaiBKo8RotyulwKaYgrifYfDQurFSkVcKpSKclAyiGDyd8+UbGY6wM/pSD4
         +35hM2fsLU8M3iDXRfx/9rda0r+3B1WUoEFIe4zqlRvAoBACln5nDJ46KRR1xJI3Iuh8
         tzAQ==
X-Gm-Message-State: AOAM533Pt6NW4AZPNB/OUFqB64ZhyCqWW/0rxSl2XvVYeKSBOO8iw+8u
	vjy4E3hjqr8Zw1bM1efvbvI=
X-Google-Smtp-Source: ABdhPJwj7p5+0U1s2wDDtgIp6S8DU9Ork5GcqR5ptTZgWx++zd6FdCVSWeBVL4rkVoWN3qrFsyhk/A==
X-Received: by 2002:a17:902:6941:: with SMTP id k1mr3590018plt.270.1598269767148;
        Mon, 24 Aug 2020 04:49:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:fc89:: with SMTP id ci9ls3587729pjb.0.gmail; Mon, 24
 Aug 2020 04:49:26 -0700 (PDT)
X-Received: by 2002:a17:90a:b00e:: with SMTP id x14mr3527077pjq.203.1598269766685;
        Mon, 24 Aug 2020 04:49:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598269766; cv=none;
        d=google.com; s=arc-20160816;
        b=hBbcA4+u4wB8oB0+U5vhxmEtChSKEnq9bnwXaVRGlq3dWsNXZjDwT9Y3v+53yJ7yAb
         5rrphz5lYphm8aSd0n09XOSI/qWGCJPTNhxzdBxnG8TsOb/MCSc/QZTdFITluGYy+Bkv
         Ja+vi/VdzsKE3mxFruV4ZCurkehwZo3jXBVUIAO1cSuz4sndRrBi0MSaO8ubSP2chmqt
         uPDxI6u5NY1JammOPCMaHy4rG1wW7do+7mEVhFlW5PgJ23//Vr0lSxEIEcvvYnsU2Jwz
         OMSUSgVZhfUMm4FR5LTMOpBabxNWEbQ4U0dZmqvqRzWN6TvDg2v2jSsYlR9CsheXZxVU
         t50A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IfIxkLsRxova3XYkDm6i/K8H2HRLaB3EQ7huQjW3f6w=;
        b=hErrJGkhyz8u0IfFpwHqQ+f8FFVstcxkCEQN5iKRGRewongD4jTim8WCdpZr6S3vM3
         cepZX0syg19SoHcac97F9l9ZNqhnoqwbWT51BsFl5vXMGwzYRWxqu4QBqe2vVOTv8nhb
         zNHs/9jhCphqQp6Zgp3cCXiGjE2MA6j9aVrOm3Sab5aYZievIxUejJCRzGBcJ9aPqe54
         9ujOGbgSUfOHfecYXBGUWAuVf3Ck+FnnbzAfUTa3CrTx8yiVNYLFlkvzuD9BV0DNmgGf
         yIwXw3NF7HAqvzOloO2QMxG2B3/9q1Y17Pk/G65SCSAqxlr3yg69LiDNUbgVmOc9/3Ug
         v3Yg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ifu4mAhc;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id o185si56871pfg.4.2020.08.24.04.49.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Aug 2020 04:49:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id u16so3545794otj.10
        for <kasan-dev@googlegroups.com>; Mon, 24 Aug 2020 04:49:26 -0700 (PDT)
X-Received: by 2002:a05:6830:1612:: with SMTP id g18mr3040756otr.251.1598269765865;
 Mon, 24 Aug 2020 04:49:25 -0700 (PDT)
MIME-Version: 1.0
References: <20200824081353.25148-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20200824081353.25148-1-walter-zh.wu@mediatek.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 24 Aug 2020 13:49:14 +0200
Message-ID: <CANpmjNNf5pr=0hKVo92M9fEnCy7sYbv==6Bv_sVSmn=rZi7JEA@mail.gmail.com>
Subject: Re: [PATCH v2 5/6] kasan: add tests for workqueue stack recording
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ifu4mAhc;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as
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

On Mon, 24 Aug 2020 at 10:14, Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> Adds a test to verify workqueue stack recording and print it in
> KASAN report.
>
> The KASAN report was as follows(cleaned up slightly):
>
>  BUG: KASAN: use-after-free in kasan_workqueue_uaf
>
>  Freed by task 54:
>   kasan_save_stack+0x24/0x50
>   kasan_set_track+0x24/0x38
>   kasan_set_free_info+0x20/0x40
>   __kasan_slab_free+0x10c/0x170
>   kasan_slab_free+0x10/0x18
>   kfree+0x98/0x270
>   kasan_workqueue_work+0xc/0x18
>
>  Last potentially related work creation:
>   kasan_save_stack+0x24/0x50
>   kasan_record_wq_stack+0xa8/0xb8
>   insert_work+0x48/0x288
>   __queue_work+0x3e8/0xc40
>   queue_work_on+0xf4/0x118
>   kasan_workqueue_uaf+0xfc/0x190
>
> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Matthias Brugger <matthias.bgg@gmail.com>
> Cc: Andrey Konovalov <andreyknvl@google.com>
> ---
>  lib/test_kasan.c | 29 +++++++++++++++++++++++++++++
>  1 file changed, 29 insertions(+)

These will majorly conflict with the KASAN-test KUnit rework, which I
don't know what the status is. AFAIK, these are not yet in -mm tree.

I think the KASAN-test KUnit rework has priority, as rebasing that
work on top of this patch is going to be difficult. So maybe these
test additions can be declared optional if there are conflicts coming,
and if that'll be the case you'll have to rebase and resend the test.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNf5pr%3D0hKVo92M9fEnCy7sYbv%3D%3D6Bv_sVSmn%3DrZi7JEA%40mail.gmail.com.
