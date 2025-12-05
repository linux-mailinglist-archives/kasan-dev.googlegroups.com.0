Return-Path: <kasan-dev+bncBDW2JDUY5AORBQVHZHEQMGQEPXTRKUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id ABCF3CA6059
	for <lists+kasan-dev@lfdr.de>; Fri, 05 Dec 2025 04:39:02 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-37d29739b60sf10145301fa.1
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 19:39:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764905924; cv=pass;
        d=google.com; s=arc-20240605;
        b=YDTQ1a9iXrC6/B1qMvj3Iov7WPOx+Cv5rcO6RLW60enTSq59mfS8ASLIcbxcUOGqQN
         tRtiWg3dt6R975nHf08IWD8wgPvFPlPYSGz6zeL1C6Zie8qB8aRed+A3m/YRwVWkCAR9
         0FtVEs13uQ40oAewe5qAQebBeA6vvZKnabg8oDYTtTGIzXFzRzQqPghEKrNhi/0VrHkP
         DdnjILZEmxuqXVbqtECo//g1RWKyjNwXIH6XYq8TzQDYcknkX5sbcPszgWzr7DnTdd/9
         rV5A1YO5+zMHPF8HthjruuPdVItmutTMnU9Rus/ZrR24Yi0ZGP377E2wApKAkpRme5z9
         ifyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=ugBAfoFt4KTfBTGQPu9r28fFaKECDz2xdYPeZyZcPtE=;
        fh=5AeEO25fC/GF7EGLfreLtj/yvmPlWeeG95MW6JqccZ4=;
        b=Pg/4Wi2v+PbGpsH9a5ojEjaUvoyO2cKDsTd9sPwmRrP1+1FnLJ5GVpEtVaFUMc8pq3
         x/5+4zV/Cu+FkzrDs/h4RfkpcDANEXRy3yTgnIYZInhCeYKMJlBEfyL/Dh+mGWvRYnep
         UJs0iEfXv/ktEaiIMhjPUVnnJVMsSvGFoDFSwmhZDreMBtxDSCGvQwblSz5SJVKlTXnJ
         hhDCDg5LRX9w87gk3pNLNsJvQQpkSPCh5UCRH/Hmuk4c6Jx1UBgxz7qL0sKDBvcawyKH
         EK7bHJb9SiyrwtbSaTF9tLylIkA4eKneEINBsfauXwbZ4MUY7FAgqpyap/IByTAVopga
         esqw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZN+cKey6;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764905924; x=1765510724; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ugBAfoFt4KTfBTGQPu9r28fFaKECDz2xdYPeZyZcPtE=;
        b=nRvkHNL2K6vQvZwxl1lZgZ+j8XygshdYB9toRA5q7WQI9UQBrRsYgzrZuFcxIb6HIh
         sfz+1briTUyl6E9MkCImT//lXz2f9ugQGaUkqHtMV0DIdGMarcvBizFjmdzPnb9xRJlv
         E2VcOCyN5iTGjWSSlzgqWa2rtKZAXtc+KnY6+fbflxRv4pVR1L3UNZbF6Ugrl4siN1XY
         CThuqg+zRWFEOhuhnbMh3n7jk/sQmYEU+XCChQlZE3N9e+Q4E/zoPUDLn18cBAourbsi
         EMzhD64q8ax1NJ9IgOf7pvoT3IUCwbM21eyNREBWrrImDZVnrc0grPrFMzMDopXyE0mL
         wXTQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1764905924; x=1765510724; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ugBAfoFt4KTfBTGQPu9r28fFaKECDz2xdYPeZyZcPtE=;
        b=lpHpqxTMpP2GNy6YpuSH+2bwmAzqeOlBTI6NACAt+7jLcMsYfWRweiyJDoDTe2t/Od
         8gwd7bTgWMZ2KeIicdk0699jCM4xQyFMlyu+44074gfodJkO28ixe6B1Y8KPMaw57EZp
         Cj4+0ev96QxRtu1mOKa2N40MZ2vDgrMoRpC+rzqYGCHHfi+kaHiXnenlFVuc3VUn3SoH
         qGQEm8GBuF2zLdKWV+lWXAn2mCCg2B2E0US0tTUin1hYw5exDMbEhwz6gc4j6Pis56CP
         prbWrkUs4xEgdKSZF6nttHI20ibPzi/4aFRRv4Dz+Bitn5jFgZGdxiO2AueNVQHhdaY0
         j9BQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764905924; x=1765510724;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ugBAfoFt4KTfBTGQPu9r28fFaKECDz2xdYPeZyZcPtE=;
        b=txQN7Zvh+M9AS+ZZBgZbZWK38Z6t6je2mQGz807C9eZqMGTvl3S6LjJ9gBUAA952Ux
         KQuIskIwzVucx5D6iK/J6tq4BrTsgNbuOz1sCxpXKtOeDG6Xg2FLvyuwk6LHcmXxJEqC
         X+FLbpZTOGXs4FoMSOtKFPh6JVe6oV3q5znSfkrU4nS39zi33G2DVV/NR3SxZqtZWayy
         CdaetRAjqfm8t9tTH1/KQt/cfEzEDAo6lIsFILqP4FbIEoJOceoun1wwR7qxvWn6dEUe
         r7Ghdnh24v7UwR5dbkZXW9bdmwyceHFytLuV+dXrimh7qWo/oh7FTtVC166pKhm5KzvE
         vQ6A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVL7jCiuuHWHoup/bOl0zXjmOQcAFS5pXrtf/BQy4ysknXEVfL9zY2jGA4meDG7yENltNuXZQ==@lfdr.de
X-Gm-Message-State: AOJu0YzN3ZibPTlPc4bqMEUGDN4oW7jW/NFVbk4YWFAyWFiv9TuSOA22
	KvaBmB+bISovehR+7I87h0QvKKJSUw9AJ+ENAne0nomm/6okiauJpNOf
X-Google-Smtp-Source: AGHT+IEq40Q7NmUoYtf9EILv7KCQwpQBPJKi4bNq51kBDl5WvrKfEowDQJg3RnDBGBdRAWmPq/ph8w==
X-Received: by 2002:a2e:be9a:0:b0:37a:45a4:e874 with SMTP id 38308e7fff4ca-37e6dd19aadmr12444941fa.14.1764905923273;
        Thu, 04 Dec 2025 19:38:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YS1u80k4T5oeiB07/lFReqhRCbYL63uwlUSt1YYJZKFw=="
Received: by 2002:a05:651c:4355:10b0:37a:3088:a94f with SMTP id
 38308e7fff4ca-37e6e939e67ls2394221fa.0.-pod-prod-07-eu; Thu, 04 Dec 2025
 19:38:40 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU1TWLVBavmEf0kv1C6BscxqLzuwgNL0xlVVyMHjvntMIeiY8M+2sPShRIqR+9Z8sVN7MMw/rTnSvk=@googlegroups.com
X-Received: by 2002:a2e:b8c5:0:b0:37c:dc91:6287 with SMTP id 38308e7fff4ca-37e6de3a066mr13766511fa.36.1764905919923;
        Thu, 04 Dec 2025 19:38:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764905919; cv=none;
        d=google.com; s=arc-20240605;
        b=CDnJR+DVDbv1muQYBqzXiMgPmasf5kI/gjhgSBp8Z/UO2+iyuJm4Am2psW/bhFWbRY
         fABQgNkKgX9+k9I70qyG0Sb/ekhiRR5OVRe4JTnpWkPOB97QMs4RP97fYoU5VjDons2g
         tauFsWJP+ck2E0pUPekl64Ma0ywjn0bVj+ZOqYJmM6XkoiWDlBng+beG7ehjvOHpPFPw
         KRIWUtVH/eYPBbHXIN2ENpEICiFcSweOQcNFLa8wH9SKazGanfCZ+jOrmVIyqPgnpHRt
         Igwwu8a7cBtcecaQblKIKQrIF0F2N5UOJSaqgxCvxC9BsZqV38bCBpj7xPPI0gqnhpXG
         aMNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=fl+caqWL5n0dvFbZchH+YmZ4xMTXCKbX5vTDeE5p1t4=;
        fh=uzpXLKSILLBOQCEIi6kAobGs+eNxNXzCou0xOwbTIiM=;
        b=L1jIEI+b8rMulmpatp0uBTa16/a0jxbOkPwwMGrNVcdKQzrUwQIg8bMhLDagX7mMrS
         ApXOgtRg2cxkTP/5EGO2vX0Vsik7RfTLh3cvMrY7Q3iczFJHAh5oE7IAGHfvJ0b404tU
         jIofh3XJ6/67Y8rNQiLh/PHf8BF3IpWTSzlX9nlFLCCmbITiuj7YPLF3QU8mTcKIaFxM
         mVjwiLj3AI7R6XxV73HBYbm7fqLeTuBk943m1qy82N8jlp0wB3Jo0ikD5GOR2FZrLO1a
         jxC+lK385aPVO1nR7PAvSu6oX5SCVngdtSU8vMLhOoAz7vRsTII01GcIRLRUHc1gAh2P
         r8eA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZN+cKey6;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x333.google.com (mail-wm1-x333.google.com. [2a00:1450:4864:20::333])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-37e700c2581si549531fa.5.2025.12.04.19.38.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Dec 2025 19:38:39 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) client-ip=2a00:1450:4864:20::333;
Received: by mail-wm1-x333.google.com with SMTP id 5b1f17b1804b1-477a1c28778so22509935e9.3
        for <kasan-dev@googlegroups.com>; Thu, 04 Dec 2025 19:38:39 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWoLyjAji1OKkLLjNYibkEY+5iw9phe3hjdmTNGwW226j44u5P53LEwrghCG7qjetfz5IvsISRpFvE=@googlegroups.com
X-Gm-Gg: ASbGncu+fV/+uDbW/Tb6dLz9g8wcE/oD/p6XCinmLb80ucd1HHWshTwyqGe78df59MZ
	SnGmPpSLzY1h5z9odLrtmRWMpv1JdxHflzA7ep4IYxez+RZVBhg11N830m+XMFQx8cplYkMjtpK
	ouk3bU9Ls4zwM5ch33DgouQAFTnmw6O7nkYquNgPcK6zoqzj5iFtu8oA2GGAYMgiVaYT+m57nLV
	lJPsv/YY3JvW4AGvjDPMoKClYYfzdHB2TvQISoTRlyK4Ywt4MA0NiI40HYO1lCsWFkPefLj2iHM
	qyqNFgieaxT4RAzffW82VirhOnT7JIIo5neMlixr8EY=
X-Received: by 2002:a05:6000:18a6:b0:42b:4069:428a with SMTP id
 ffacd0b85a97d-42f79514c50mr5364434f8f.12.1764905919003; Thu, 04 Dec 2025
 19:38:39 -0800 (PST)
MIME-Version: 1.0
References: <cover.1764874575.git.m.wieczorretman@pm.me> <873821114a9f722ffb5d6702b94782e902883fdf.1764874575.git.m.wieczorretman@pm.me>
 <CA+fCnZeuGdKSEm11oGT6FS71_vGq1vjq-xY36kxVdFvwmag2ZQ@mail.gmail.com> <20251204192237.0d7a07c9961843503c08ebab@linux-foundation.org>
In-Reply-To: <20251204192237.0d7a07c9961843503c08ebab@linux-foundation.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 5 Dec 2025 04:38:27 +0100
X-Gm-Features: AQt7F2r4SDeGe1uHCJN0ZI3Zd_JW0xi9yGmGe6DkXMc4yWVA8HXcBjqiziEEKSE
Message-ID: <CA+fCnZfBqNKAkwKmdu7YAPWjPDWY=wRkUiWuYjEzK4_tNhSGFA@mail.gmail.com>
Subject: Re: [PATCH v3 3/3] kasan: Unpoison vms[area] addresses with a common tag
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Maciej Wieczor-Retman <m.wieczorretman@pm.me>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Marco Elver <elver@google.com>, jiayuan.chen@linux.dev, 
	stable@vger.kernel.org, 
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ZN+cKey6;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Fri, Dec 5, 2025 at 4:22=E2=80=AFAM Andrew Morton <akpm@linux-foundation=
.org> wrote:
>
> On Fri, 5 Dec 2025 02:09:06 +0100 Andrey Konovalov <andreyknvl@gmail.com>=
 wrote:
>
> > > --- a/mm/kasan/common.c
> > > +++ b/mm/kasan/common.c
> > > @@ -591,11 +591,28 @@ void __kasan_unpoison_vmap_areas(struct vm_stru=
ct **vms, int nr_vms,
> > >         unsigned long size;
> > >         void *addr;
> > >         int area;
> > > +       u8 tag;
> > > +
> > > +       /*
> > > +        * If KASAN_VMALLOC_KEEP_TAG was set at this point, all vms[]=
 pointers
> > > +        * would be unpoisoned with the KASAN_TAG_KERNEL which would =
disable
> > > +        * KASAN checks down the line.
> > > +        */
> > > +       if (flags & KASAN_VMALLOC_KEEP_TAG) {
> >
> > I think we can do a WARN_ON() here: passing KASAN_VMALLOC_KEEP_TAG to
> > this function would be a bug in KASAN annotations and thus a kernel
> > bug. Therefore, printing a WARNING seems justified.
>
> This?
>
> --- a/mm/kasan/common.c~kasan-unpoison-vms-addresses-with-a-common-tag-fi=
x
> +++ a/mm/kasan/common.c
> @@ -598,7 +598,7 @@ void __kasan_unpoison_vmap_areas(struct
>          * would be unpoisoned with the KASAN_TAG_KERNEL which would disa=
ble
>          * KASAN checks down the line.
>          */
> -       if (flags & KASAN_VMALLOC_KEEP_TAG) {
> +       if (WARN_ON_ONCE(flags & KASAN_VMALLOC_KEEP_TAG)) {
>                 pr_warn("KASAN_VMALLOC_KEEP_TAG flag shouldn't be already=
 set!\n");
>                 return;
>         }
> _
>

Can also drop pr_warn(), but this is fine too. Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZfBqNKAkwKmdu7YAPWjPDWY%3DwRkUiWuYjEzK4_tNhSGFA%40mail.gmail.com.
