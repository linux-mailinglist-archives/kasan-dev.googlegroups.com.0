Return-Path: <kasan-dev+bncBDW2JDUY5AORBQOJVLEAMGQEWCBFLJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D57EC339A2
	for <lists+kasan-dev@lfdr.de>; Wed, 05 Nov 2025 02:13:39 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-4775d8428e8sf1430845e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Nov 2025 17:13:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762305219; cv=pass;
        d=google.com; s=arc-20240605;
        b=KWrBJnR8KiNVP30t5qjsH2xxsyri5+qfbVV3BM2FjRJ7KO+LyuWccKlS23lvsFns6N
         5IWbK9f40N5hap+vU3jLoxwpCXmy8aQR3V9OZNpJ0e0kNxPwJpbGevoOsUnh/rqifZJq
         PSLwti4P4w5o/SFCLDkFPOJ3D2aetRwSylaRwkrRm1FiTLQDs8N8RUb3Vc7/L6IjCts3
         BkkexaZq+zi+s4nhR4wwWsw8Tcp2XQt2LsYQbmj0iJkEGg6YGeO6vpkma4dpsZjTo5Fu
         TkEii73zQjmRBn63RUFOY4LvbaQST1v9pjoLx7sB/hzfWT1476sILqwktsN3uXFxlNap
         auGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=wNxaODmn3jZgV/saov8wGTuS6qyH/isqMQyp7v1pCRo=;
        fh=d06rSIkHxS6ythytjj6/etn+iIW4v22MBwWzIPBAAVQ=;
        b=fal8LDCygxjAvDGB+8HnNt2jwl215TNXwF2f0xJ1Kw7gvc1CvRB+PIP/4Ebcmx3++g
         BTbqLBxH3dG21LTOJkgDViVstgESCRMKFgEFHvHbqI8N0RN5ppQVs+OMwfl5q4iIcfW+
         OClc+wlDbUPe+U5lSBqKfmzQEiMAuZISmVLLhZTLdchRsNIlTIQ1qyi4xXOsP+VHBtse
         oGPrxXo7etwPIxd8hYJEfy3HeMfbDf1mG/eK1+xQl8ScRA1AlFNQa4gbStmuCr9dnJKx
         4pLGKr131+Zh2xKUcgUN9BKshatPpTyQqFkRCaKh7U0W2gKX8Jj74LF0WxoCbnAGysNC
         N4Hw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=dJX7zmSA;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762305219; x=1762910019; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=wNxaODmn3jZgV/saov8wGTuS6qyH/isqMQyp7v1pCRo=;
        b=dZDGJAlmrjLAOfmqd6T62HwCrOHGchq1rA82XYKDsBhtLFK6eBEpB+32GbE2iHdM99
         YjaHAj0NHJbLdPAS1fIuReJVlQfvQ47gyajZp0BuvxG0BMy4UM0ugdHR7/HWvLvvHHsS
         g7Pfq0mQtXgCIpf2LPcaH7QUMyAoZqNAJQ6ckTvI5yOoIX0vmPSd7Uz87fWHBQFOoxBU
         i4WuCSZ8mYmG5dUVuU6Ck6f4nDF2wmldaWZfm/GjKF7rnW2Ns/6XzpoR0Y4nfgBo0Qt5
         XwghN0ju28YbvEuRuLe9o5njcMOjDFjZ7tSLI4/7ekA42EeXHz2EDEqTuZRzq6juxYsW
         xypw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762305219; x=1762910019; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wNxaODmn3jZgV/saov8wGTuS6qyH/isqMQyp7v1pCRo=;
        b=JUICvbfWEBCQzt91YVodVQtWoHjs3OSxXwGSW+gSe87QP2DSmazlZ9h0UKoBd5/l7B
         4jjYbiVq8bBAe2FFA9em770dcwiJajtT/zqS9QtitgzcOHdsiQA7uvb79OEvMK7TEWux
         JiyJsezRq9Dh+iWHT9//f1kxFHh7f86USVF4zuYYQKxssiJoLpbDctJhtS/TWBOPUjwH
         E63YIr1QZeB48bLSAwmGTlB/St+HHq7EO/i0FTRQVogaRBN3TZAPKymLed6qnquymwam
         SniVMVECRmp0Z/LnBLnlIO8cMmIohJzfEsdNeLK9V0X8KRq5nfTWF3W3/4R6V3aJqvJm
         Eexg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762305219; x=1762910019;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=wNxaODmn3jZgV/saov8wGTuS6qyH/isqMQyp7v1pCRo=;
        b=VLIHhw6jsfHHzv+h6Ib88SiV9MxiObBn2Tes5aVTHhjVwY+ZjOF+AqSW/Nm3qMwxJH
         VQkSFyBCRNp5CnYEnFwWu7Ru3C6JSeu2P+1Aw/z76c1ovshEEeGogkfnyWNPFWMI/gLo
         ftcYaTKXcE8yPHX+Fs00SYpnnQv4dah6CUAygvDXTqMFp6oGf2zEj9KnwrbwgIiqhQMx
         7mLkO9sHQmPxvsM2SPK65LeFxkhW7eixZDA2SweO3JERHRx1bn7VuScguIWKlPFQ73oA
         /mHrD74xGov3smN06Q97Di+SkTvanjIzrmTB68ZhCk/ixAXvwSBm+DDmm8tblMt5rE0V
         2kaw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUPw06FdBNgFd+ZvFFdecNNoK/P/RoUefeG+kcT+2XqSBjGuaympFMV5CyJzfP59S9R5dku4g==@lfdr.de
X-Gm-Message-State: AOJu0Yxy1izUL60f6IT0i9v5mlJsIxLJJXXIRpCbqlDcTomMfy0BTAWD
	gh2o8zr9fftUMpCJ+7es3FxOPm48ei/P0OmiRODfok2sXw8Bq6TXpCx3
X-Google-Smtp-Source: AGHT+IGtiYaFCCxChyyzBk3HLsccevSCA1Jvyb0v/hyCQXbHxAfn3ZVeR7zsAJioSifcdb44iN3qGQ==
X-Received: by 2002:a05:600c:a343:b0:45b:80ff:58f7 with SMTP id 5b1f17b1804b1-4775ce26f26mr11143975e9.36.1762305218584;
        Tue, 04 Nov 2025 17:13:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bGOfSMNOf1EsYTqk4iMHqQyh7/HZBpxM8NI3e3Orsxpw=="
Received: by 2002:a05:600c:6099:b0:477:5d94:4ab3 with SMTP id
 5b1f17b1804b1-4775d944d2dls1132095e9.2.-pod-prod-02-eu; Tue, 04 Nov 2025
 17:13:35 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWdb18ECp2xk8JKKp+rku9nEoiFYHGxKTEHIVMgpewGCHgWzSnU3EOhYThhxZzQ9HVb6QAUUHmBIRE=@googlegroups.com
X-Received: by 2002:a05:600c:a00c:b0:46e:4499:ba30 with SMTP id 5b1f17b1804b1-4775ce1af9emr11630285e9.30.1762305215629;
        Tue, 04 Nov 2025 17:13:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762305215; cv=none;
        d=google.com; s=arc-20240605;
        b=HrrQc3GxBi5sD1hQWBHL+MiP7Vb0PLIGAcS+ms9JYOOS25uOP6WD+Y2Vqxz35vn+dm
         83pwPB4K2gIJjOqVvaxHLhSZga6r2XaIOmPAhEB4rhcdc0i3LEBKNms520tYQgV/svyh
         f3oo1VesU0iSsg4e9xppvWOVuPXWfPX4xbLuvzvzSydAlHhtLXzbeQqyMx49bd5lE3bf
         jqj0KEXDLetkqeCzot/GvdrJNWua+DyXVn9dnHtpOLnmDCnTCtB62JFqtemb+OHoNfGk
         ttTm8w+y4kaQRdaATIWdt/eDvOne7LD3bPFFnGjd/nyteGxj3fwosIZPj5io+ks2YRsA
         bB/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=87sj/urHj778WRrZXS7UN3zWW0S51mEqs7jth+xOmiY=;
        fh=IpxdK4B17UAlDyPH13+Czh0JqAYy3Q+t5/Pe2RBS5Vk=;
        b=h5sRxeMikvmw9WHKX7IEdQugXJxydfmj8vkKAr87qWs8MZLY08MSfuljUOTGbtCYNW
         lJVftqPNKhqdzsGbNN8dJBw6ULDid3Z1apLzhTFtFJGGknB5Cyp3t/mdFKgooMQa5Cr/
         CdtX3kQFKL4I/4LGcMFN72x2zXvNyme90GRKEqAi0wemDlT/g2xYq3RBsk7RTk3mD4Q5
         cU4QGVl7lbR/rTvP+3Cpy/dUbKUshwiz4yIh5JMgM2s1PKoJobCHjuKCZZUfeJWZhNc/
         I08ssB5wo0vf8qBy++rlkJQkljrr5ypEnSHZ7v4jXiGEWzUOr6zThyR9h70wwJiQVUqy
         1w8g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=dJX7zmSA;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x432.google.com (mail-wr1-x432.google.com. [2a00:1450:4864:20::432])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4775a0fe5fesi242605e9.2.2025.11.04.17.13.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Nov 2025 17:13:35 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::432 as permitted sender) client-ip=2a00:1450:4864:20::432;
Received: by mail-wr1-x432.google.com with SMTP id ffacd0b85a97d-421851bca51so5182554f8f.1
        for <kasan-dev@googlegroups.com>; Tue, 04 Nov 2025 17:13:35 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWF0eMhzwSKY8e6m7f7qVQW9b8ZSV6liZI1DCAONNA+7OPVGE4IXWFnz8MS4ay4l87iWTu7M+IsU14=@googlegroups.com
X-Gm-Gg: ASbGncs2kXJFmaaPxg8dtKTQhzZO0pQMyYu97wIGQUoxaT//1tKt+UKHJVO1SiVb/Wx
	lTGvgCMF6Wn9DtZNPMj87DlM5aaSWQI+qkpsQOeHtmnnYRCcQFlVHtorGn2Gsi7XVYtuLGJ7ME4
	hQcMqt6pkq9ZZUxzrJkMd1R+/Xr82X7HPatR40Yu4Upv0XGdnSfqc+qIfiA3ZtgE6BTsEh61R2K
	3Lew17vjghvJ9So6s8gUxFJGkxuyuGR0Vc1IzoxfmFNlI9VAeQIqSJ7s0iWEVd4yiQn5E5qoiCw
	JJTMLpKIu8O6zAR9e+C1MhiRUD5pKw==
X-Received: by 2002:a05:6000:210c:b0:429:b751:792b with SMTP id
 ffacd0b85a97d-429e33064femr697123f8f.32.1762305214961; Tue, 04 Nov 2025
 17:13:34 -0800 (PST)
MIME-Version: 1.0
References: <cover.1762267022.git.m.wieczorretman@pm.me> <cf8fe0ffcdbf54e06d9df26c8473b123c4065f02.1762267022.git.m.wieczorretman@pm.me>
In-Reply-To: <cf8fe0ffcdbf54e06d9df26c8473b123c4065f02.1762267022.git.m.wieczorretman@pm.me>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 5 Nov 2025 02:13:22 +0100
X-Gm-Features: AWmQ_bliHxtRFT6WIWfcnl1BDrwXrFHVP_La30Dhwz3XgybJKCGbopAvefwnxWk
Message-ID: <CA+fCnZdUMTQNq=hgn8KbNwv2+LsRqoZ_R0CK0uWnjB41nHzvyg@mail.gmail.com>
Subject: Re: [PATCH v1 2/2] kasan: Unpoison vms[area] addresses with a common tag
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Marco Elver <elver@google.com>, stable@vger.kernel.org, 
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, Baoquan He <bhe@redhat.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=dJX7zmSA;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::432
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

On Tue, Nov 4, 2025 at 3:49=E2=80=AFPM Maciej Wieczor-Retman
<m.wieczorretman@pm.me> wrote:
>
> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>
> A KASAN tag mismatch, possibly causing a kernel panic, can be observed
> on systems with a tag-based KASAN enabled and with multiple NUMA nodes.
> It was reported on arm64 and reproduced on x86. It can be explained in
> the following points:
>
>         1. There can be more than one virtual memory chunk.
>         2. Chunk's base address has a tag.
>         3. The base address points at the first chunk and thus inherits
>            the tag of the first chunk.
>         4. The subsequent chunks will be accessed with the tag from the
>            first chunk.
>         5. Thus, the subsequent chunks need to have their tag set to
>            match that of the first chunk.
>
> Unpoison all vm_structs after allocating them for the percpu allocator.
> Use the same tag to resolve the pcpu chunk address mismatch.
>
> Fixes: 1d96320f8d53 ("kasan, vmalloc: add vmalloc tagging for SW_TAGS")
> Cc: <stable@vger.kernel.org> # 6.1+
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> Tested-by: Baoquan He <bhe@redhat.com>
> ---
> Changelog v1 (after splitting of from the KASAN series):
> - Rewrite the patch message to point at the user impact of the issue.
> - Move helper to common.c so it can be compiled in all KASAN modes.
>
>  mm/kasan/common.c | 10 +++++++++-
>  1 file changed, 9 insertions(+), 1 deletion(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index c63544a98c24..a6bbc68984cd 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -584,12 +584,20 @@ bool __kasan_check_byte(const void *address, unsign=
ed long ip)
>         return true;
>  }
>
> +/*
> + * A tag mismatch happens when calculating per-cpu chunk addresses, beca=
use
> + * they all inherit the tag from vms[0]->addr, even when nr_vms is bigge=
r
> + * than 1. This is a problem because all the vms[]->addr come from separ=
ate
> + * allocations and have different tags so while the calculated address i=
s
> + * correct the tag isn't.
> + */
>  void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
>  {
>         int area;
>
>         for (area =3D 0 ; area < nr_vms ; area++) {
>                 kasan_poison(vms[area]->addr, vms[area]->size,
> -                            arch_kasan_get_tag(vms[area]->addr), false);
> +                            arch_kasan_get_tag(vms[0]->addr), false);
> +               arch_kasan_set_tag(vms[area]->addr, arch_kasan_get_tag(vm=
s[0]->addr));

set_tag() does not set the tag in place, its return value needs to be assig=
ned.

So if this patch fixes the issue, there's something off (is
vms[area]->addr never used for area !=3D 0)?

>         }
>  }

> --
> 2.51.0
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZdUMTQNq%3Dhgn8KbNwv2%2BLsRqoZ_R0CK0uWnjB41nHzvyg%40mail.gmail.com.
