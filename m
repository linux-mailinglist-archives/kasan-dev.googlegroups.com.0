Return-Path: <kasan-dev+bncBDW2JDUY5AORB34E46VQMGQETFE4JPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id BE1498114E3
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:40:48 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-67ee8a447b3sf29364846d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 06:40:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702478447; cv=pass;
        d=google.com; s=arc-20160816;
        b=e3r6l/beHatPwaU4wyq1AJj9Gk+ci6u5v1k7IVbT+U5KNLmsdkI5vs82LYPF3HuZ74
         FtJ16U0yJ+b/Zs8ZZVFbavjcM+HdTMGePXKLgk1OmW8azr59YomLYLyHRCKtCSRlJ7Kf
         o+IICMVnM0c5MflExd4TQ8PL+DQ6SdhbA908Zv5Dt3g7SbhyXi6/PzI18q3y79Ov+1Hh
         +Uc9n8OTGjD9jf71rSa1DIiUV3Lhb94Wzr0INQ0XXliPhqf1xSPxPfWTWa/7sz0U6j/Z
         JjyWH1CDcUSpvgp8sbYeuJr06KMESRrhlHZ8oxwfqkbSoJ5cC8UM1ZIlNIr2JsX0zJzK
         gYhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=TEFWbXWdnTkkzpEWomnDRg7YE/HixuEISHTH/f3yRiU=;
        fh=F6+FGML87yHqRev/l5aFDmOtQouYoX3HLtF8iNVpDI4=;
        b=K+UnUUbnyuMZvmRJ4eAZ+DA/dp7NGxVKriHjF8fcmdUuixmqmcLqNYtmhlsuj3a57m
         RFwbpd1H7/ag2lIjDLtEMwTnHr2uq81RhBVRcssm5WhFk43OFZUHZpG20ErgBpMAT8Z0
         3JrjgyQnzhIGADqObjd7/8GmyyKlnRR9yiNdUFLoPxwGiKn7gVoyfxBG9rVTwuQyAiOU
         gT7z2KO/a9R6BupMGOPSrp35tKyWb7pKnNi8robHE7Mb8iKdFu/k5kLXdDDXcJvZkcJn
         DGMUsPBEWDEA89zyn7z6rywnouaPPN6NigF1t8W14N/edrVp9q9xIaloA9TvldWs0LB7
         BKbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=O0WRorCF;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702478447; x=1703083247; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=TEFWbXWdnTkkzpEWomnDRg7YE/HixuEISHTH/f3yRiU=;
        b=Hd37BGZAALtjDvVaS09zt2ZLABKYxMOmWikhaNDH/R5MvDjOkNhwQ4jroIvpAWy81X
         yS/UxPP5XZEu2QD1QxAa9soWoSvrsPDHlPipYGNWbUC1hziXRIQVhN2nAyPZhr9fqtUa
         q7msWeKsHU8tiTU5y70D2Lz2bwHcdr6h1PE8EjZQb67HUGdkgWwkumhljJx+zc+LUJ/k
         bUStzggbADiT2B81G6qrWOER1RTDMB7Dyn/TJPYt8KI2lgZghS0NUtAopqj+epW91mNB
         vUXbnpC0D1TbCn7Dt7zh4lBR4/P++SRjl+KPEJlBeuxrFLc5Gqs/ewO1P3iYeg0oV7X+
         BZpw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1702478447; x=1703083247; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TEFWbXWdnTkkzpEWomnDRg7YE/HixuEISHTH/f3yRiU=;
        b=bSKz+zAR2XfB54DJDN5grTVeomPCF2++gZ/Ha4/9hZUjCaSRGEb22BZfIwS5r7qcwf
         5T3wNIh2mxkuqhjhbK71Lg/jLYgGqzxKV+KzNbu6bTZe4pfBQ2wzL0O/boZgyCReEpcP
         CdDRhzoa4fcSM20/1lgiqc2PcVuTVB6x7lRZNFKX6ecbuiF5RHu37qv0UMuO1la9okTN
         M2ZaMAs16G1A9nuvbaxvYywsGydXw3ju0z6BVBgqYeGQi6uv9lVqWM9fJewipxrdOwba
         flOGwXDfrobx0vYRlqVEqP1qEvjO6cb6jdc1e9D7zc9tDOmXwJSlvz7TDcYJvH6bMA3V
         Y7jg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702478447; x=1703083247;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=TEFWbXWdnTkkzpEWomnDRg7YE/HixuEISHTH/f3yRiU=;
        b=vfswHkTnfKwwQzQ2kN2L5U6N8jU73nwMs0OmLd+W26k8rCsmj5CYNSfF+Cu0hzcpf7
         XxqVeVMlLz0geqnt6n6bK2H0ajXMvZQPPslMtTJ7gsTHRjrkJ3Mp+XulclxYvKyioHYy
         4nWOEc4wdUesgP33GleduWLHNs+1oARxWb7P28BS87dgJvm193vAAwUKCyqaZYIv3OWm
         9h0fbiJbASaSoy1oRImCdKTEpkES46fTvK4mtkMDg2mGOEmSdFZFtHNBvfGl15mdzWFJ
         lfJ9wBcVpRPdWHJKt2dLEu68kXG64JTzz0gSC2Q54Z47gGN8ANlW8U/RvYPu89b1h3ZQ
         6sgg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwASheeEjkpjcG331hN625kA3mVG0tbTpuYIaKCaxWMh59mWSnb
	TmeekCj40Y5hx2eGWj2U61g=
X-Google-Smtp-Source: AGHT+IHvYhmPiR6mou6ruYqa7m2AOfv+zSheuQCfj/s/4FD06LxF2MbI1kAMhyADTiKplzu5HoArTA==
X-Received: by 2002:a0c:f84c:0:b0:67f:18d:8ee5 with SMTP id g12-20020a0cf84c000000b0067f018d8ee5mr487730qvo.36.1702478447522;
        Wed, 13 Dec 2023 06:40:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:bec6:0:b0:67a:9173:54f9 with SMTP id f6-20020a0cbec6000000b0067a917354f9ls1055837qvj.1.-pod-prod-00-us;
 Wed, 13 Dec 2023 06:40:46 -0800 (PST)
X-Received: by 2002:ac5:c937:0:b0:4b2:c554:ccff with SMTP id u23-20020ac5c937000000b004b2c554ccffmr6097090vkl.11.1702478446635;
        Wed, 13 Dec 2023 06:40:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702478446; cv=none;
        d=google.com; s=arc-20160816;
        b=P2k0S40gDiyv1xzxRH2YdJQtdt/3D99nCTglsVWuCbBj2zB8eKDhmnz5pW/1FHyOoe
         F5aAJT2W55QFQDk0RvhU5IiguR/vXWpUhezmvkhyj9LhT32KljfS5fHtH14LBEfe9Guw
         UypfEAmCkRj3MExbdGrSlsHLmYPztnLJ8RxLSDg2UJ+pRj4yPnvyS/+EQldjHb5n54J9
         c6c6jZSUxUi6CgYCWkQPdoMVSiOSS35uplDqbx02C6e3wejya+QrZqCQ2bVC6RhTnEK0
         YPKv5ZE82b4/GBjZQiyK1dDrOHW60TjcZwh/roJ/2s0iTYy4OcRHR76hNl1OnLshoHCN
         BFsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=t3mJDSsBd+gLTGFYfrkyu9tBgFHp0rV5RVCzftSRiIQ=;
        fh=F6+FGML87yHqRev/l5aFDmOtQouYoX3HLtF8iNVpDI4=;
        b=XL7ZvlAo6KU8/KCkk9UI8ToXH2nl2URjEfWMdYc2jRj4mj/estsXH4/StQ3EGvytaZ
         boXuKpugk7jcQ0AXsEc7ZDmdPoA4OZtoJ8Ni6EECId5F+hPPaDhCFsiMXYYCu9DpRFAy
         8loQb6GcejCVbjZdRIYrrRDzB2yZSJq09KInesuWg1V6vf/Oa5KFuFVNlHhSJ4CY4jhG
         FBirW0Otm/WyTnLWeLJNB92cpjp69d70vYX9n5MaMauoUaGpC32rpGEkRTW0OLv1kRa8
         oqkyIwLkSohsefBjgNqo1pogPcyG05EedXH5aKW7OwEjGhziCD6j6p+v3L17GKYwsDeS
         eYgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=O0WRorCF;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x102b.google.com (mail-pj1-x102b.google.com. [2607:f8b0:4864:20::102b])
        by gmr-mx.google.com with ESMTPS id l41-20020a056122202900b004b2f93695f7si1169439vkd.4.2023.12.13.06.40.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Dec 2023 06:40:46 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102b as permitted sender) client-ip=2607:f8b0:4864:20::102b;
Received: by mail-pj1-x102b.google.com with SMTP id 98e67ed59e1d1-28659348677so5414029a91.0
        for <kasan-dev@googlegroups.com>; Wed, 13 Dec 2023 06:40:46 -0800 (PST)
X-Received: by 2002:a17:90b:e0e:b0:28a:dcda:a101 with SMTP id
 ge14-20020a17090b0e0e00b0028adcdaa101mr1926855pjb.47.1702478445662; Wed, 13
 Dec 2023 06:40:45 -0800 (PST)
MIME-Version: 1.0
References: <cover.1702339432.git.andreyknvl@google.com> <432a89fafce11244287c8af757e73a2eb22a5354.1702339432.git.andreyknvl@google.com>
 <CANpmjNM9Kq9C4f9AMYE9U3JrqofbsrC7cmrP28ZP4ep1CZTWaA@mail.gmail.com>
In-Reply-To: <CANpmjNM9Kq9C4f9AMYE9U3JrqofbsrC7cmrP28ZP4ep1CZTWaA@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 13 Dec 2023 15:40:34 +0100
Message-ID: <CA+fCnZcGWXbpwCxk5eoBEMr2_4+8hhEpTefE2h4QQ-9fRv-2Uw@mail.gmail.com>
Subject: Re: [PATCH mm 2/4] kasan: handle concurrent kasan_record_aux_stack calls
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	kasan-dev@googlegroups.com, Evgenii Stepanov <eugenis@google.com>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
	syzbot+186b55175d8360728234@syzkaller.appspotmail.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=O0WRorCF;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102b
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Dec 12, 2023 at 8:29=E2=80=AFPM Marco Elver <elver@google.com> wrot=
e:
>
> > -       stack_depot_put(alloc_meta->aux_stack[1]);
> > +       new_handle =3D kasan_save_stack(0, depot_flags);
> > +
> > +       spin_lock_irqsave(&aux_lock, flags);
>
> This is a unnecessary global lock. What's the problem here? As far as
> I can understand a race is possible where we may end up with
> duplicated or lost stack handles.

Yes, this is the problem. And this leads to refcount underflows in the
stack depot code, as we fail to keep precise track of the stack
traces.

> Since storing this information is best effort anyway, and bugs are
> rare, a global lock protecting this is overkill.
>
> I'd just accept the racyness and use READ_ONCE() / WRITE_ONCE() just
> to make sure we don't tear any reads/writes and the depot handles are
> valid.

This will help with the potential tears but will not help with the
refcount issues.

> There are other more complex schemes [1], but I think they are
> overkill as well.
>
> [1]: Since a depot stack handle is just an u32, we can have a
>
>  union {
>    depot_stack_handle_t handles[2];
>    atomic64_t atomic_handle;
>   } aux_stack;
> (BUILD_BUG_ON somewhere if sizeof handles and atomic_handle mismatch.)
>
> Then in the code here create the same union and load atomic_handle.
> Swap handle[1] into handle[0] and write the new one in handles[1].
> Then do a cmpxchg loop to store the new atomic_handle.

This approach should work. If you prefer, I can do this instead of a spinlo=
ck.

But we do need some kind of atomicity while rotating the aux handles
to make sure nothing gets lost.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcGWXbpwCxk5eoBEMr2_4%2B8hhEpTefE2h4QQ-9fRv-2Uw%40mail.gm=
ail.com.
