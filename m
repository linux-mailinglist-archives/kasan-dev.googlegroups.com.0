Return-Path: <kasan-dev+bncBCCMH5WKTMGRBUHUUTDAMGQE62PLCPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 93785B5935A
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 12:22:10 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-4b79773a429sf81226951cf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 03:22:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758018129; cv=pass;
        d=google.com; s=arc-20240605;
        b=GHKmX70lSZWGH1SnF5SAmhueFdN1hQu1BjJvFc6VRBvOIwaDNIwkwsKigIT6cioFcK
         18GLW7zNUbgMvrH3ao0oWa9nABj8awZev7rDiXl7dv6ePCVYvYN//BjuGBS8YJ1RdcTV
         dMQ0IBkCdzROECrmMUki5dbMUdIPAB/MLPBJvJedUKeQr9hvhbwHr1efMnVunXKcjtYD
         4QFSxa7vHaIURdM/ybWVFzi1ViahbNRWXRGnpji1wJRJrKLUuYE5Mvgf5/1RUKIkjlKo
         qtfGbbcKnWA5JTsl8lOjzYP43h7kaYpioz3remMLQq/SL6DE9VamHLMJQAT8RmTfzVZ8
         W0UQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KuGYjNmIpagusq/mb3NahVGnXW7eEhNKvdkx1EPul5o=;
        fh=4YMYMSk2qrswI+BzqXSgeay0EyknrUqKzCewTma7oqI=;
        b=QkR3YaKknXOcCUD0umahLtwJ81gg2kNbto20hwXifdqZBSpciIaP91TCw/cW5WhWaY
         LgwC5AI9Ux1BOoG8fn0zUmeFAbrwNDkebP4fr62gq9sN2xT8M1NOqXud87R7kRYYauR6
         F4STMaRfYrb4/gS3jOTdW4NKDQXDhiQPfuq7M3SVVwavHf0XEnTNNOSaXcmUaXFzjo8C
         0B0VVGV4Yj99KszJoT0gfK8dThpO5OvEGZ0AeznKKECUG6LDhzCEruhgTXYor3SANIvU
         KOHDeUFAC7UglC5Kpi789XCS6chAMVH1hiYEVa5c7c7SHj0Cf+mG+xRz8W6nM5Y+EBo/
         G1lA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="z9ofhw6/";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758018129; x=1758622929; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KuGYjNmIpagusq/mb3NahVGnXW7eEhNKvdkx1EPul5o=;
        b=Y1wcKrJMpdofU8KcCuKcOjRlTocgY2tGKvxkKij5lKoIT2MPCvXK+Fe43Dc7bL74AS
         WD4eYNz/5VJMfW8Zvfxjubho3YFFpDsQfRzaneJxtllE7rYVmPmdB2r6RX4YYBH+MyVI
         SUjMi7nuxGvw5+vCT9Tn0M608rJkksNLXcn2TWhg6/Ifg4fl8kJKRy8FgDZbB7BWDSyV
         F1ra41FjQ+Tij9tlZ5Xjw96JTXQ8R8Qdcm+8dQKUVhxm0UJbTo6kzHATAQx+yQHpW0Ws
         3pZ6qXyVd/mfIsLCqRpix9jsOxwPrfWyZauAVPfHz9kNQx18j+5wcOsoTrVPm++pgCwg
         buYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758018129; x=1758622929;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=KuGYjNmIpagusq/mb3NahVGnXW7eEhNKvdkx1EPul5o=;
        b=RIxsaNhb2JfLnWGfpKHu6om++dZeP3yB+6xAUcrx8r4d8jPC1fTNU/cW4P8aNSfchi
         BVbPyuteXQzmI0teOuGjfvyM9+S05LfI8Ka4I8UJvV/d8tY83zHQQXAcl7iGcwyurr8T
         VQEoSfS0vm0V2aQOizurW93ni6A6fr+gUBFmezZF7pKMmh2S/EbPTvpz/JIn/syDWyFw
         QwDV0iUqp4H0IJt/KjY9DLwr1p5aDHFaTPXyAJplsRAtTbkZT5gigGMghE4KoDvCjxEb
         VJLbXLO9C0fb/uqJTTTsnx53HTUK/GKEXdSPn7Jme3GHty1jXoZPFibw4rw1Lu20lXVo
         rRRQ==
X-Forwarded-Encrypted: i=2; AJvYcCWtmiFxPoMbiEoa8pNbsaIZyEm0D57QeDPD9dkC6RwKu6O6syjOoFDCsr15cpAqQbH+/xULxg==@lfdr.de
X-Gm-Message-State: AOJu0YyhbjQctmAOdHdJC8YV5He6Y2JcP9c4Zw9mIF47JRZtM5QeGvQM
	OsMxzVbLM3Q1ubg1RLpZUqb5qRMt6/iKKzAIfa91RsWQVGqudWxPQqDP
X-Google-Smtp-Source: AGHT+IFuRzBtgwFhUAujWsg0dn+X6jRVA+XAG8PX7jvqZ8Nz1Md2mt7VK5sUgT/ry8db1CxI5O4vjw==
X-Received: by 2002:a05:622a:a18:b0:4b5:d60c:2fc8 with SMTP id d75a77b69052e-4b77d09239bmr233885931cf.71.1758018129228;
        Tue, 16 Sep 2025 03:22:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd75K0XoWxo1zhoG93PzLh7qgsJ8IWNZ3Pjkx7D63I/6bA==
Received: by 2002:a05:622a:3c8:b0:4b0:889b:bc70 with SMTP id
 d75a77b69052e-4b636ccb94als108959081cf.2.-pod-prod-04-us; Tue, 16 Sep 2025
 03:22:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVciIpQOGxR16Biq8ks8WnSP7RadlkaKiHyQRerufsjFGz3rxFx0284iZ4GoX2ezCzB73APo+9E4Wo=@googlegroups.com
X-Received: by 2002:ac8:5882:0:b0:4b6:33e6:bc04 with SMTP id d75a77b69052e-4b77d05a075mr166392431cf.60.1758018128302;
        Tue, 16 Sep 2025 03:22:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758018128; cv=none;
        d=google.com; s=arc-20240605;
        b=Y9NoRqLn39Zx7/vqZNFFhWqUGakkw3Hu0OGprWcmKY/pxan/4zr293RUnt52FodwHz
         wfatNaAmA+8xt6zEGxJSFtKZ1Lhv3vJtzHM46/dHIoRH2dSlyFTFe4HwYb7JJ8HzM0x0
         7YZRdQDTl5DtVpMtFNT6OzuQnrDnnJ7JnhpxOPa76yRHi+uAc9A0IWdSR33YezE2blI6
         x2uSYj25O+W9n1b9/lunvDK8slcRuSpowW4/Gefl5yVzpVBfzFkFJjBTHYWQ2yt1f5oR
         /9M2D3uLjJh1EdK+boPlnhS264PX+GcRXo++suBMDz64nGZ3+TxjC98wJOHP0IpdO3A/
         UQIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=8fDdVkJYP6n8rFxsmmwdyCR43GJXYJ4e6lkQY1k5jhI=;
        fh=hUh0b1IdHmPRw1wdKo8eNpSjDcEUaTvNk4QpwuvgN/Y=;
        b=lk3RNBe7DRZF97ILhMNiLajVsO2JvbWLGF3EThwylE1dxXxENWsRcz2n9FvAyQ8I56
         z/3hwp6O/LkzjE47UQsMVQ6VvH4VwBwBn4IFuU8lU83MPliLt5hcfOU+dW/J8+5buawR
         1yM58b607bYUBRMZlNNHM0lCndHbVLZ2mPrnNdFWM7oLpy3fVxAu7RRDuJRfPIjn1dEu
         JLi7Vp6991Kuxa/sYT4BNEf2IDQVcOpoVkyem2DdJufWnfTtfld6O+p9a+nmbbsYtObO
         ZrGymbUhXc4adBxm6EHwJIUpAzkbFeEBW5S1Po85txCZJYL4Zy8PKz4a6tyxkp476x6M
         FPOg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="z9ofhw6/";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2a.google.com (mail-qv1-xf2a.google.com. [2607:f8b0:4864:20::f2a])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-820c87de2dasi56888285a.1.2025.09.16.03.22.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Sep 2025 03:22:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) client-ip=2607:f8b0:4864:20::f2a;
Received: by mail-qv1-xf2a.google.com with SMTP id 6a1803df08f44-778d99112fbso35022526d6.1
        for <kasan-dev@googlegroups.com>; Tue, 16 Sep 2025 03:22:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU+o42jlhkfDyoCd9b9oYJUv5P6EFqqPLD/+gAfBEHdDNqRd43tHVBEzvZnTL+dQPJggQfRaSbsEPg=@googlegroups.com
X-Gm-Gg: ASbGnculZiOgk3Sr/Ynmbb5F0bKDfkpIH6Zw0rR4q7TJxsgm74dcn/euzhNDLO54pEM
	vyPTeRPQEZTR5hDrWaDH7iRSOjonYQk4286vDQIY5U48aV6O1vl6Wg3L48sEpyB2psm2nypNdJM
	WimxdE0N1wPqtviLN37rx9xKP8ALZyGhT6SX1pexZInQXJ4QefrJvzoIrpeOZxGf7Fufbu5GgYE
	CfxsqSqRy5CJ6hJF+f8bTC8b2JTpT57nYELd/lrl88igDdSFkg2cCE=
X-Received: by 2002:a05:6214:1c4d:b0:781:a369:ef8c with SMTP id
 6a1803df08f44-781a369f19fmr98103496d6.16.1758018127627; Tue, 16 Sep 2025
 03:22:07 -0700 (PDT)
MIME-Version: 1.0
References: <20250916090109.91132-1-ethan.w.s.graham@gmail.com> <20250916090109.91132-4-ethan.w.s.graham@gmail.com>
In-Reply-To: <20250916090109.91132-4-ethan.w.s.graham@gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 16 Sep 2025 12:21:31 +0200
X-Gm-Features: AS18NWAvlqXEHGPKEvaBnkig3ksosFgvoGuvVmEMsd87qxp-V32sXYdPaxYq0Tg
Message-ID: <CAG_fn=U0dOBumngmQQ1cna=SZvbDXjJ8NrVUZyCHY5dzJV4rVg@mail.gmail.com>
Subject: Re: [PATCH v1 03/10] kfuzztest: implement core module and input processing
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: ethangraham@google.com, andreyknvl@gmail.com, andy@kernel.org, 
	brauner@kernel.org, brendan.higgins@linux.dev, davem@davemloft.net, 
	davidgow@google.com, dhowells@redhat.com, dvyukov@google.com, 
	elver@google.com, herbert@gondor.apana.org.au, ignat@cloudflare.com, 
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net, 
	kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com, 
	linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, lukas@wunner.de, rmoar@google.com, shuah@kernel.org, 
	tarasmadan@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="z9ofhw6/";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2a as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Sep 16, 2025 at 11:01=E2=80=AFAM Ethan Graham
<ethan.w.s.graham@gmail.com> wrote:
>
> From: Ethan Graham <ethangraham@google.com>
>
> Add the core runtime implementation for KFuzzTest. This includes the
> module initialization, and the logic for receiving and processing
> user-provided inputs through debugfs.
>
> On module load, the framework discovers all test targets by iterating
> over the .kfuzztest_target section, creating a corresponding debugfs
> directory with a write-only 'input' file for each of them.
>
> Writing to an 'input' file triggers the main fuzzing sequence:
> 1. The serialized input is copied from userspace into a kernel buffer.
> 2. The buffer is parsed to validate the region array and relocation
>    table.
> 3. Pointers are patched based on the relocation entries, and in KASAN
>    builds the inter-region padding is poisoned.
> 4. The resulting struct is passed to the user-defined test logic.
>
> Signed-off-by: Ethan Graham <ethangraham@google.com>
>
> ---
> v3:

Nit: these are RFC version numbers, and they will start clashing with
the non-RFC numbers next time you update this series.
I suggest changing them to "RFC v3" and "RFC v2" respectively.

> +
> +/**
> + * kfuzztest_init - initializes the debug filesystem for KFuzzTest
> + *
> + * Each registered target in the ".kfuzztest_targets" section gets its o=
wn
> + * subdirectory under "/sys/kernel/debug/kfuzztest/<test-name>" containi=
ng one
> + * write-only "input" file used for receiving inputs from userspace.
> + * Furthermore, a directory "/sys/kernel/debug/kfuzztest/_config" is cre=
ated,
> + * containing two read-only files "minalign" and "num_targets", that ret=
urn
> + * the minimum required region alignment and number of targets respectiv=
ely.

This comment (and some below) is out of sync with the implementation.
As we've discussed offline, there's probably little value in having
"/sys/kernel/debug/kfuzztest/_config/num_targets", because that number
is equal to the number of files in "/sys/kernel/debug/kfuzztest/"
minus one.
It just came to my mind that "num_invocations" could be moved to some
"kfuzztest/_stat" directory, but it can also stay here as long as you
fix the doc comments.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DU0dOBumngmQQ1cna%3DSZvbDXjJ8NrVUZyCHY5dzJV4rVg%40mail.gmail.com.
