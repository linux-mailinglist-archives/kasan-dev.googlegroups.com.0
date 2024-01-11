Return-Path: <kasan-dev+bncBDW2JDUY5AORBYEFQCWQMGQEBCYJTCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 935F282B13E
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Jan 2024 16:01:53 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-50eaa8ce853sf1121356e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Jan 2024 07:01:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704985313; cv=pass;
        d=google.com; s=arc-20160816;
        b=mJRUTKkytKPTP3apvA7UfWJRItyC+HqaOjdWsx/RW7v4kvT3LwtUCMxJ6XWuP9KTjY
         /3hFCJVze/8K88xkEVaQOezj2rB3fswwosyECKSrT96YW+h+/tciOsVchw360pRUMj56
         dJGNrMXtaHTZX6Bhq8PhbNF1dsYuK2WtYsBv4GiCJQ1mG+tbkY9oujYHq8Cbs/EVWMyD
         8J3uLzV9a0g5gUXtw3ew4FxI21JVYbkb6KHl0/bV2tNVuu/EhEOj2/01HNb0//e7kyXn
         RXsTiu0g4oybLImmZiZooSVaaAtrz4eJ2v7SKz7U4NlhKbmHeml0tQNy1NUEOfAY4+IK
         XGkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=5E9aRNNGkyJe4VH97xNRo9g+/3rBhgBI69N/6qiPXjw=;
        fh=FqvYNlCLWIDjWYFr+DwzftQJfCKN/UXJm7cBpYfn7zs=;
        b=tAx2n45r/aS0x5RfOBbxdbgN2QxhAwNTVycp/t0BuMsRV2Y3dmcmkWPkeJptdxMfDi
         BbLR1ToDeqtHT/an5+htzAnKl4ws3pKRULof0Ml5oBCFDhsQoiC9UCtbhLvlMYgLqoXd
         jQcs0Np31H2dzOpK5gHRy9Ab4OCIutj1ce4L4uZCQCu9l9jLGpqITa1/ye+IzO/447fO
         Q1bt2XK0A2y5zgTFetjoEv+jGXjRgQcOFAOi/PkVlpmSl4A1LNT3gF3WEjlYewhK7J1O
         OfP7ffj+ei6Xkcrf1EGjX9xj6gRwdLedSoWOHAT4jmQv+t2btbdDdKgBnF47m193sM0F
         EM5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Bg06o40C;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704985313; x=1705590113; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=5E9aRNNGkyJe4VH97xNRo9g+/3rBhgBI69N/6qiPXjw=;
        b=U6aHdv902sRB5Vr9f4+bCGBe7TPl1qdL+/vLZHow2ANFElmk2HwwyugiS0dGpqhGAv
         iwEke+3KWWJc755V+QHjcWo20hZHuJIZWnawj+H3TDmSclW3+1X12/lpWeYZnNtZU3Ct
         ARsYpywLzSXgXjYoo8IezNIJlQortJ6XzxWkT57EhO54wFFnNUjDk6axvnzh2IfL9dWD
         QxamOA3awhQljdXyvBk7RtSLY7OMWd0szQWHx2WoL1AMEkQrvgzU6bmnlyGSjd1TRp2o
         QhyR+JHIYJc1jDoILVNbymETvV7E3QEsPTMOfpDpP0wyB/klZtmelpgqkHDdBOR6P6X4
         NslQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1704985313; x=1705590113; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5E9aRNNGkyJe4VH97xNRo9g+/3rBhgBI69N/6qiPXjw=;
        b=hCIE1i3ttSLI6JfXJuzUk2KHOL4m/3TmRKeTDPrMyG8/8G9TvG61hWaVDiLCHCJB4h
         yNqLr/ZpzqADItmAsuc6u3LP+BojKPGv3qy2zt4Wt+QsueycdXq7OOOdSXnGOBn8p7sJ
         zlb/uq4BUqaTN5XSyl4SOCOnWZTDFUGxsMo3zbAezZ/hqCEDN9P4Kh5VRtpYizssqhe2
         3TZiiVwNVYxn0Nz9lm+9/t4258OPyiUNOXYE0KvtJkpaxrUKOm08wQbr/N8NadQ8p6Vw
         D++nSN2DX0oRZ0EVric7a6DmTtao45T0ox87dOKdj3ySaxmHfDBrT4/6Oij4F5PaYvft
         j6OQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704985313; x=1705590113;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=5E9aRNNGkyJe4VH97xNRo9g+/3rBhgBI69N/6qiPXjw=;
        b=MlFAg02HyKtAcgMlD3SDhZRSdcla5uLT1IeeDN4xBt5RLWNdpPfg1vwmBMLvIKbdfg
         T1J5tsq35tcNed4UMx+ve2InHZm296D/l058cnycPvL3ROPa6KXqH6rK9p4cAge9P8qJ
         QDlo50xr1l+wn6YCp8BbWiZKA/3Nw9pH6WUuKVGAe/tGAKKdFrAfmPWUs8iUGMuoB14O
         WXEe96/+vEmGq2MSDzqjBDA5T6WYhkZj5C9m3Ugq88I90LYGtEPaJ1C3nA4GRhwbiJVW
         Bf1tieCxXB9h0qKXSzYKncTJtoNXO74po9GBYo3YpRIomnArgUXPlATzC8HSSKPKipMa
         CqvQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxkJWiV6CB0gS2mZ+rIxtAR2lsipTrmbKZTeBbT/bUsGx0nqXvF
	fJmW+5sKZ39xRDVnwI3XTdE=
X-Google-Smtp-Source: AGHT+IFM9YQrXTu+OZ+Ne4PfXjMq7HozsGCkUfC1ztD7w4D2iidURYSFJq2g6UmD4MPhzxyFLRcugg==
X-Received: by 2002:a05:6512:48c6:b0:50e:ac90:85fa with SMTP id er6-20020a05651248c600b0050eac9085famr491387lfb.22.1704985312346;
        Thu, 11 Jan 2024 07:01:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2803:b0:50e:7281:9f03 with SMTP id
 cf3-20020a056512280300b0050e72819f03ls1084629lfb.1.-pod-prod-00-eu; Thu, 11
 Jan 2024 07:01:50 -0800 (PST)
X-Received: by 2002:a05:6512:312e:b0:50e:bf53:ee77 with SMTP id p14-20020a056512312e00b0050ebf53ee77mr589595lfd.24.1704985310011;
        Thu, 11 Jan 2024 07:01:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704985309; cv=none;
        d=google.com; s=arc-20160816;
        b=Optra4wX548AISoWdqBODRvSdXezS3zsOD8EOvwHFGr4Rlcx8GLt2QMqBhdV/kjEkv
         OSqIAQmpT4z20AgsOqJsdu06bErY/wqcYNQDyKMwu5vsMF7WgMhaoNmUV1IDwHJwSYyP
         v0vMogJFWY8niBJxBhJAP01trx3TTnwSjxNKORKMBui22YSj7sk5akiKXmg6nCbNq1SY
         8kx28+zdICFTT5F5zd+rf97XpWTGZgrGOU/6ChdQOZ1ATIoGFrMxAOdKoNESLGiEnAMM
         7DBELdyp744To5wSmePnlX5uIa8oVYoB/Me+L34FgMUabB6lZlah2czE9l+w2/JyLATD
         HRIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=nlU9CairkGmPdE7mvp0HFWtFNt4+Gjb65TjgR3sW9KI=;
        fh=FqvYNlCLWIDjWYFr+DwzftQJfCKN/UXJm7cBpYfn7zs=;
        b=YD1g0UBGwqiV9dF+a9gR62GFjbM1Lh+hTtUDXWkfBa+SCCmHATGfOLLWt6XHFHSh4g
         /Je3nLOYfrLY3TlUOWEtLasKnaXzw39lYcG/e8cFC9m5G5eOTvOOcnuUxC29RlnEPrqL
         2a5hsuHRiVqQGDJwsYAc2/cElxs7qi3FVNRhi6h5KD0K0OTDyFGu/mBUkySZdnRdi1kw
         zsCmB7FHQF2IbsZxBicxrkFnjQfzq5vednFnKjHzLquHlt214Jr14+F2/czeAGNcBUw7
         DrTLVJR6Nxfz/pX5F5Z0mY/vNzRVBXLN2aIJ2Fli+Lt6cuhyws/hAWvepxaTzSjQc34W
         Cvug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Bg06o40C;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x431.google.com (mail-wr1-x431.google.com. [2a00:1450:4864:20::431])
        by gmr-mx.google.com with ESMTPS id p6-20020a056512234600b0050e6b19b855si44241lfu.11.2024.01.11.07.01.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Jan 2024 07:01:49 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) client-ip=2a00:1450:4864:20::431;
Received: by mail-wr1-x431.google.com with SMTP id ffacd0b85a97d-3368ae75082so3616521f8f.1
        for <kasan-dev@googlegroups.com>; Thu, 11 Jan 2024 07:01:49 -0800 (PST)
X-Received: by 2002:a05:600c:46d5:b0:40e:56ea:d9c3 with SMTP id
 q21-20020a05600c46d500b0040e56ead9c3mr551988wmo.47.1704985308895; Thu, 11 Jan
 2024 07:01:48 -0800 (PST)
MIME-Version: 1.0
References: <202401111558.1374ae6f-oliver.sang@intel.com> <b1adbb1c-62b7-459f-a1bb-63774895fbb3@I-love.SAKURA.ne.jp>
In-Reply-To: <b1adbb1c-62b7-459f-a1bb-63774895fbb3@I-love.SAKURA.ne.jp>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 11 Jan 2024 16:01:37 +0100
Message-ID: <CA+fCnZcmxQn+hSsJf=WOsYX4HY4u4s=cRKje65pEcAQ5gpqANw@mail.gmail.com>
Subject: Re: [linus:master] [kasan] a414d4286f: INFO:trying_to_register_non-static_key
To: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, 
	kernel test robot <oliver.sang@intel.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, oe-lkp@lists.linux.dev, lkp@intel.com, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Bg06o40C;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431
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

On Thu, Jan 11, 2024 at 4:00=E2=80=AFPM Tetsuo Handa
<penguin-kernel@i-love.sakura.ne.jp> wrote:
>
> Commit a414d4286f34 ("kasan: handle concurrent kasan_record_aux_stack cal=
ls")
> calls raw_spin_lock_init(&alloc_meta->aux_lock) after __memset() in
> kasan_init_object_meta(), but does not call raw_spin_lock_init() after __=
memset()
> in release_alloc_meta(), resulting in lock map information being zeroed o=
ut?
>
> We should not zero out the whole sizeof(struct kasan_alloc_meta) bytes fr=
om
> release_alloc_meta() in order not to undo raw_spin_lock_init() from
> kasan_init_object_meta() ?

Yes, already sent a fix:

https://lore.kernel.org/linux-mm/20240109221234.90929-1-andrey.konovalov@li=
nux.dev/

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcmxQn%2BhSsJf%3DWOsYX4HY4u4s%3DcRKje65pEcAQ5gpqANw%40mai=
l.gmail.com.
