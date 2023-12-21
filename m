Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIFZSKWAMGQE6DTCBEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id BC6BF81BF7C
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 21:14:25 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-3368c707b03sf467914f8f.3
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 12:14:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703189665; cv=pass;
        d=google.com; s=arc-20160816;
        b=NxbIobIjjqoR7nEI6HuAlftabHv+UktU7VnXauknT9GsQkHiv09f85oUre9ucVB52f
         WPPfwFMIpSMMRKwSardEouRGxlpjP4j50SXyrkm45VGjQrd3Z9/uXNv/cW/adUSK2D3j
         4oNLXWGd9VNUtjjomZLnKT7DLKMBenPvAVFpqEpyX8xcXPK/tTuSUYMPi9OS0O09D+Ka
         JXZPZVmYLElK0Nc0/ha0qn4yKW46G1CHlLLTx89WiTGyimyR7wYGWeRwDNAufHVmOfCo
         nN4hCbJ2MWDvGeJwz8+rlny55Ir4HtmtvCrfYzheNc8d0ISHh+ozg5zCbexjm+Gq0ueM
         7Xmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=c2VchKnh0ZmZZd+oMTe2x03rUlZRGsTP2avgDBlsa+w=;
        fh=Ahy40MSztyYZMnTonwM1XBgEig8egyoCalPOkrHuKkk=;
        b=YH0+B8iILqtCyVTV+ceW9SPTrGlmZRyKlftnbXr+r19svJja9NmEovlIOCQJUNZrxw
         iLH89hai9ieetuTxtX/KyRPiag4qq4go3HAwQZobYitXYqyrR0Q8EP5Ei5/p0AAaAxpN
         P3EaONxHd2/VQU75zkdn1QWifTGsgcpVu/hiQ37kkz+T8hESgawcXDnmJemb1Lr/3NN5
         3gCKIVhFQd/f+HvZOydymocnNOhiLYy3ABZGfykLp2yIfPZK7g6sCD6Jj5C9DyoeXt43
         Ioh4l2JC4FwThyXvOO6JSEwcqts69Nu3hjaG1CSi4GlCCHAIMt3hN0oIO+THStKPqI04
         TLcA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="U1CIqW/4";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703189665; x=1703794465; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=c2VchKnh0ZmZZd+oMTe2x03rUlZRGsTP2avgDBlsa+w=;
        b=BV5dgWdHw2eOSri8yLPPDmeFgmYbStiYk4azAjocaswUKfOyjNm2apGDW30g1eoJIu
         3LJFQPBnTEJJRfe3EMdOq3AJzsN9IenmN49F2OgDr5/SEJdAoh6TOqrKM+H/LAHbDH6/
         YSvUMhW0YerpiLzlCq2xvULf1Ym4DN1CrfVZ4sTlcx06AftBILtXaX2VqesRZeetmDbK
         6R55LsznVCQFjkvyXIkK2MYoS5jYdCVHj6BHfsRwvqjl59OX97gmT9n0dsxaBdrM9mwU
         1ABr4+OPHvQl050FV+z8ev92MaiqI2LDvETmTm7hz3A9/UQMoYHwOlAIoyj+iBN/Dav5
         aOmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703189665; x=1703794465;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=c2VchKnh0ZmZZd+oMTe2x03rUlZRGsTP2avgDBlsa+w=;
        b=UJrJUwE5eU00CnhzYXoX35lToFiW4RFcbie5pOt0W7ct+9Ssp4HfUJKib61UZrx4Uv
         uSSEq2HplRnL4adHUpCKNPiDxruAptE2kOtpwzg7nxqxTUXA0AWEtcADLWB+mj8Xc4BG
         uWoo4qYTwrz5YSSCnaAt5Sb0JTL1O1xzrfqlcluINIqn3YFduVVh6J3z3OJmEw6+gcWV
         LkqXGJfNe2hnmhlWdbu17v7zPThgtkmuc/sFfBT3EKgITvbYI2S1RIWQaQUPfltUdcvr
         lCj+5tRaIAbs2Ie0MUdufq3Wiamn8BnAsdZgu4CFrI1FDL/Kzl3OK8Tp0bTe32ZlCqlV
         L57Q==
X-Gm-Message-State: AOJu0Yxp4ZtVzYsR0g6VEGYA/fjTTCDYEBKf9CprKXV1KWmuaiC8z6u5
	7hIuDDHUDk2s0yIVeIUAqrM=
X-Google-Smtp-Source: AGHT+IGff7+zCSfd3iz8yszkEQfikdnbBGf4Ks4mKetp/ixGt1mZemFQQsw6svNUAm/YW3a7vgCEog==
X-Received: by 2002:a05:600c:474a:b0:40c:6136:10e9 with SMTP id w10-20020a05600c474a00b0040c613610e9mr153576wmo.109.1703189665141;
        Thu, 21 Dec 2023 12:14:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3544:b0:40d:2f89:3349 with SMTP id
 i4-20020a05600c354400b0040d2f893349ls677344wmq.1.-pod-prod-03-eu; Thu, 21 Dec
 2023 12:14:23 -0800 (PST)
X-Received: by 2002:a05:600c:1e1b:b0:40c:4a25:8cf9 with SMTP id ay27-20020a05600c1e1b00b0040c4a258cf9mr155768wmb.50.1703189663039;
        Thu, 21 Dec 2023 12:14:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703189663; cv=none;
        d=google.com; s=arc-20160816;
        b=JYNZi8qkavdyGDL932o4535/iw0pessQdd1FIpDRfSTSF2OFNiyc3fN/GaaZkyDgc9
         qi7eScHAxcFsFqF3IEWgRYL9khAVKMM5gTj4mRqUy+AACtQx60tg00+stNS8BM19kJu+
         TlYB9V61XsyGk5x/T1ZIFYAiv7iMMw9VW/jCUiyB4yR6ltBFG4crmgfbq8wUbJm5mPC0
         Ffg4LgC6w4kV1olYe9H5qCT3R+wC6NoRjU1YFoJK6jveLz+n7rN5s1g0X7cKNmttMli+
         CX8HxNqRzKc0DgXsA84/5fqwXyQkSHRMWWldQKs68qhZfgP6fS0iRBUVh4vI0v2jeq6w
         AfCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ijpi7yL8jJKP/LTHTn6tiHQRczMxthGLWkutDiKOvB4=;
        fh=Ahy40MSztyYZMnTonwM1XBgEig8egyoCalPOkrHuKkk=;
        b=V6JfClPffr9/g0YTCxaK8mS/kCo03DHHtI78Ryk1vQke1DkShkg5Cl5Eif0LJicZ/t
         ZL6T/YhM1A5lH33dDHvzpXurmM9sF7Wcv3HmILH9BkM6onPG45EYRWiBDzKPH6L4ac5k
         wOMVy9/V8TZc+MPDxkiViYX80ctJV0u37Mt2Ud8mThbQ21owqk+WCD0XZdUKhtkhc5x2
         IHAbkZ7pR+dQ14l47X5IeRGiI4x7pz+FOy5yKN1axKJOgLiEB2ZF+iLA72knhzQtLfWA
         75Bsin5sdGUPIZ+JisG0fZnXNMwNZAKsoJPu0LoSVGDRiEoGNKNkvdPAAuomA/vHgz1T
         HKuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="U1CIqW/4";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x132.google.com (mail-lf1-x132.google.com. [2a00:1450:4864:20::132])
        by gmr-mx.google.com with ESMTPS id az15-20020a05600c600f00b0040b47a6405bsi366152wmb.1.2023.12.21.12.14.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Dec 2023 12:14:23 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::132 as permitted sender) client-ip=2a00:1450:4864:20::132;
Received: by mail-lf1-x132.google.com with SMTP id 2adb3069b0e04-50e305530baso1514053e87.3
        for <kasan-dev@googlegroups.com>; Thu, 21 Dec 2023 12:14:22 -0800 (PST)
X-Received: by 2002:a05:6512:3767:b0:50e:644a:d384 with SMTP id
 z7-20020a056512376700b0050e644ad384mr83656lft.129.1703189662207; Thu, 21 Dec
 2023 12:14:22 -0800 (PST)
MIME-Version: 1.0
References: <20231221183540.168428-1-andrey.konovalov@linux.dev> <20231221183540.168428-4-andrey.konovalov@linux.dev>
In-Reply-To: <20231221183540.168428-4-andrey.konovalov@linux.dev>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Dec 2023 21:13:44 +0100
Message-ID: <CANpmjNMJM0zp9qmxh0MkAfKTLgzkcxyraGMp6JKSf9YquW4WMg@mail.gmail.com>
Subject: Re: [PATCH mm 4/4] kasan: simplify kasan_complete_mode_report_info
 for tag-based modes
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Juntong Deng <juntong.deng@outlook.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="U1CIqW/4";       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::132 as
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

On Thu, 21 Dec 2023 at 19:35, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> memcpy the alloc/free tracks when collecting the information about a bad
> access instead of copying fields one by one.
>
> Fixes: 5d4c6ac94694 ("kasan: record and report more information")
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kasan/report_tags.c | 23 ++++-------------------
>  1 file changed, 4 insertions(+), 19 deletions(-)
>
> diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
> index 688b9d70b04a..d15f8f580e2c 100644
> --- a/mm/kasan/report_tags.c
> +++ b/mm/kasan/report_tags.c
> @@ -27,15 +27,6 @@ static const char *get_common_bug_type(struct kasan_report_info *info)
>         return "invalid-access";
>  }
>
> -#ifdef CONFIG_KASAN_EXTRA_INFO
> -static void kasan_complete_extra_report_info(struct kasan_track *track,
> -                                        struct kasan_stack_ring_entry *entry)
> -{
> -       track->cpu = entry->track.cpu;
> -       track->timestamp = entry->track.timestamp;
> -}
> -#endif /* CONFIG_KASAN_EXTRA_INFO */
> -
>  void kasan_complete_mode_report_info(struct kasan_report_info *info)
>  {
>         unsigned long flags;
> @@ -80,11 +71,8 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
>                         if (free_found)
>                                 break;
>
> -                       info->free_track.pid = entry->track.pid;
> -                       info->free_track.stack = entry->track.stack;
> -#ifdef CONFIG_KASAN_EXTRA_INFO
> -                       kasan_complete_extra_report_info(&info->free_track, entry);
> -#endif /* CONFIG_KASAN_EXTRA_INFO */
> +                       memcpy(&info->free_track, &entry->track,
> +                              sizeof(info->free_track));

Not sure why the line break is necessary.

>                         free_found = true;
>
>                         /*
> @@ -98,11 +86,8 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
>                         if (alloc_found)
>                                 break;
>
> -                       info->alloc_track.pid = entry->track.pid;
> -                       info->alloc_track.stack = entry->track.stack;
> -#ifdef CONFIG_KASAN_EXTRA_INFO
> -                       kasan_complete_extra_report_info(&info->alloc_track, entry);
> -#endif /* CONFIG_KASAN_EXTRA_INFO */
> +                       memcpy(&info->alloc_track, &entry->track,
> +                              sizeof(info->alloc_track));
>                         alloc_found = true;
>
>                         /*
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMJM0zp9qmxh0MkAfKTLgzkcxyraGMp6JKSf9YquW4WMg%40mail.gmail.com.
