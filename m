Return-Path: <kasan-dev+bncBDR5N7WPRQGRBD4X7G2QMGQE4TKV5RY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 43790953A45
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Aug 2024 20:40:17 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id 3f1490d57ef6-e035949cc4esf2305519276.1
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Aug 2024 11:40:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723747216; cv=pass;
        d=google.com; s=arc-20160816;
        b=VPwRNRWUpJR3l4PfWTIzYzLiyl2AkZMwUNzKzYxbtOregxFVH4tp6IghJt0+rEw4Mx
         tb6yQ3W2TGJi3yoDjHkWZmngNW6ALLDnoAx/Cyb+PiD6V7RKJnDJ86bgkYSqiwh1EzMp
         BKG5GFY18C7wz+y2kxX24fC1vuCA1SNxTctslV1og4+Zz4e2PSFSd5Sx1mK6lTq5I1On
         PYzx/I7OmAKGVOk6RydgS0wMs/zsZQkRejp9hHmtlfVyv2Oxa/woNGQOobtC+5SUVtuc
         hMrhdrL0mpPvA26hHmFbtaZIoespf6kPd4tobDb/saFq9aeZSmI1eOdi+6A6MIiRfcx3
         Einw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=+0rc867bEDFe5raEHrzbd4gn7ATNlRrooYEvZbkaZdo=;
        fh=gTM95l/9DzaU9y3rBwvSIZlrugR2d0od+NTw+ZQF95s=;
        b=vdnQM1XMOP39hqDTUtwK2fynYKc/XEiVpEVrsao+dYlLSD26Dw5G14zSZuTSaDqlpg
         L/8O61rLrU6wuOMie/joGxRpP37KjWup/E7UJMO1Q4b5OW/jdaJbzuCpYxCJmLVsT7mk
         bjbrA7UDXPnHj1DzqhhKaDeHiNeuuJ/r/0aZJ4mN0YhlRADI9PYCXzZaiy7avbKpSyGK
         xz1ssHAYaONOS/NVzh1jqnxGdyLZY5oLZKlj/sW1a13eC5c21p3gJuahNp1m8Bn06fkh
         +QO3EvrfBNoCAGJwE4gI5UlXF6HST4BnNavrByZQ7kbr0sM1wfaXoj9tgZ62F6zm9HtM
         ux0Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel-dk.20230601.gappssmtp.com header.s=20230601 header.b="1mK+Zgr/";
       spf=pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=axboe@kernel.dk;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723747216; x=1724352016; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=+0rc867bEDFe5raEHrzbd4gn7ATNlRrooYEvZbkaZdo=;
        b=DqxH5vC3PadG1r5eybCbn77Ah64y13zAyQsh0iyE8I8OK6aOGy8x7YgKDObdnqyUJy
         nskX5m23FZr098ebju2GetlxYfZ4Wwpw8Z5pmjMtWM+OLZJYVboA/whOcD6PdyT0Di0I
         Cdogb5rrm4dYPj1Qt2QG514wEa3ZbvCqXRA1e686DWWH0bSUmaijeWzhA0Znc4oaNl8a
         VG7k65DjDqaoF60h3MzIpAZa2ErxTWrGqM0Em9QNlwRsP2sCMCzPSOPfVgwwHTO6wY2O
         //wNwPmbWbYsJCOkKnz9+c4n3rOsMjN1fQ69U3xLJUKRd+0UWTJ6jPsB3UuKqyV9wfYB
         5msw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723747216; x=1724352016;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+0rc867bEDFe5raEHrzbd4gn7ATNlRrooYEvZbkaZdo=;
        b=mf68HUU9ELWYW3nWcGzlO22ndZ10Xp9US3kYEC6CZvhMsbO2fgm1tVkgURbTpPFv0z
         jsW+lgU0aUgqaHInti4y08OHUWHnfyPR7qXvEmML13Um6i+OmZVdbOP7+SEIM25/LQTK
         dkiUQ8koTL+CIqnDkJfzhEOKPofHasfb3BSo0hsJcYqsAtwrOctnyDOMIOcf2aaktF4g
         F3sizbRwz4WbGcNpoP14k2Il2MLTeepBLuD+oEBpcXFCYVjIh6Bq30MDbWowSgKm7hRp
         3iemxRZPAEeZ0g9LA5Zu4TSUDjxUIgQAOGHRdBB0j6SJ74XHnh/JJ7f+wXYN8Yv1PHHn
         BtUA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWyrRutywf/FNCa7UAH6w0b0BPoXdFFvM/e3M90KaQOTMeMvcpYzsoplRiQpvI4m4S7W42Nmhb4VcC5uYmEPE0HArCEveDoQw==
X-Gm-Message-State: AOJu0YyFPZKgY0Sqfuz/4IKfVkexp6SczOn08E58QGfsc5ykTG4GLg3U
	JwiyEkv7nVytUGS9G70GIPtLUz43uuk/fWm61CATjel587k/2+63
X-Google-Smtp-Source: AGHT+IGRVx3j5KUUwJJbtcFl/4kQGqzYxmZBRhfLwhtu4h8je51u2W3U7NmmB0RGfnrzW+UNMUK6aw==
X-Received: by 2002:a05:6902:18d1:b0:e02:bc74:5245 with SMTP id 3f1490d57ef6-e1180fd870fmr817341276.37.1723747216007;
        Thu, 15 Aug 2024 11:40:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:188a:b0:e0b:e0cd:e2af with SMTP id
 3f1490d57ef6-e116bf0b94als1068140276.2.-pod-prod-09-us; Thu, 15 Aug 2024
 11:40:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXGZugRyco9fNuHzdok0AiAzpeKWgwfLQK5Oe8wXMzrjI2cmcqb8m5bgANtH0iNaHZ8D/5baIBFI9JbYkMmmQMImTDHTNwzG/kZjg==
X-Received: by 2002:a05:690c:26c7:b0:6af:9fdc:4bbd with SMTP id 00721157ae682-6b1b890d1c8mr5977897b3.16.1723747215154;
        Thu, 15 Aug 2024 11:40:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723747215; cv=none;
        d=google.com; s=arc-20160816;
        b=zjNBxJMqTxCkG3RPZyBprOnDYjAEOdR1YthieOJHBL6xN1MprtGtjRfWxAb6ykBWOt
         HbOwWTUKqO2pUkt1NB8r28NDjTfE+aLLYj7bnK2Rv20q1+GIebBNOOsi8/lb+SjmQ0yc
         mud2qR7iGAtVal4akiewcAViei0Eb0+HbJv8Q0tPERNgYs2laOr+7MC0YQSkRATqZqka
         ncYwKZ1TnP3eghySv4wLqDQGyqM+vabzXyBMlJow6hWVZeJZbSXr3j1Ue9YQRJU5rCg5
         aV2Z0Mb6eb8skQwF9rI00oZ2rfSzbnQDpOMoVP6vGnfsKSWAgLutE6Ko7ABSzd/AG9dk
         mbuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=7G23jOysGth/FGYl0E61txbtZGC7pVkDJVfmjAiyIyQ=;
        fh=EgewaEJgZjNDcWhxHhheiCrY+JYXL1cXh3yLRu6dPEk=;
        b=i6eUILuiX/sV7u4LUF5Sg/MSIDf7SifAJQzV+oZ2ChwHbuQBvyHSMNPoUEmdO8TRRp
         iB+aQNmXcY/9qJ9htjInJgUcC7pcuU/79bjtNWNpFeAQEUCtA43NGBPEE+KbLgo0QcAv
         cujq2KP+g148dy0s0NetU7fGoaFJ3RcepcVl/GQFHx0QPxbK7cHGqloDq1sjnnHY6oyg
         NJTVRmz9V93BN3Qj9bg3QmyUaSg/dqx0OPDg0OlaM0KaHujkRsHMDDH9VtNSsrbcnqfr
         MUgieFyVCuFvdjLtaVNKsFJcguKeGySWGO1LS9P4/SaXPYl/Yuq2MuSov6Md5pKsH34p
         LlZA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel-dk.20230601.gappssmtp.com header.s=20230601 header.b="1mK+Zgr/";
       spf=pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=axboe@kernel.dk;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62a.google.com (mail-pl1-x62a.google.com. [2607:f8b0:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6af997e8cd8si757637b3.1.2024.08.15.11.40.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Aug 2024 11:40:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::62a as permitted sender) client-ip=2607:f8b0:4864:20::62a;
Received: by mail-pl1-x62a.google.com with SMTP id d9443c01a7336-201eb53ddbeso1196065ad.3
        for <kasan-dev@googlegroups.com>; Thu, 15 Aug 2024 11:40:14 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV8JJ+xGF0Kwxn/QLz5xcUGh73D64jsYKbDjbVdXyP0a68ytdZO/OiWe15MBrFiNM3G0y1e7A+5H8xFxnfyb8xDrUKSTiOTiyvMIw==
X-Received: by 2002:a17:903:2291:b0:1fd:a54e:bc41 with SMTP id d9443c01a7336-2020624daebmr1154665ad.8.1723747213972;
        Thu, 15 Aug 2024 11:40:13 -0700 (PDT)
Received: from [192.168.1.150] ([198.8.77.157])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-201f03a565bsm12995635ad.263.2024.08.15.11.40.12
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Aug 2024 11:40:13 -0700 (PDT)
Message-ID: <1019eec3-3b1c-42b4-9649-65f58284bfec@kernel.dk>
Date: Thu, 15 Aug 2024 12:40:12 -0600
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: UBSAN: annotation to skip sanitization in variable that will wrap
To: Breno Leitao <leitao@debian.org>, Justin Stitt <justinstitt@google.com>
Cc: kees@kernel.org, elver@google.com, andreyknvl@gmail.com,
 ryabinin.a.a@gmail.com, kasan-dev@googlegroups.com,
 linux-hardening@vger.kernel.org, asml.silence@gmail.com,
 netdev@vger.kernel.org
References: <Zrzk8hilADAj+QTg@gmail.com>
 <CAFhGd8oowe7TwS88SU1ETJ1qvBP++MOL1iz3GrqNs+CDUhKbzg@mail.gmail.com>
 <Zr5B4Du+GTUVTFV9@gmail.com>
Content-Language: en-US
From: Jens Axboe <axboe@kernel.dk>
In-Reply-To: <Zr5B4Du+GTUVTFV9@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: axboe@kernel.dk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel-dk.20230601.gappssmtp.com header.s=20230601
 header.b="1mK+Zgr/";       spf=pass (google.com: domain of axboe@kernel.dk
 designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=axboe@kernel.dk;
       dara=pass header.i=@googlegroups.com
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

On 8/15/24 11:58 AM, Breno Leitao wrote:
>> 1) There exists some new-ish macros in overflow.h that perform
>> wrapping arithmetic without triggering sanitizer splats -- check out
>> the wrapping_* suite of macros.
> 
> do they work for atomic? I suppose we also need to have them added to
> this_cpu_add(), this_cpu_sub() helpers.

I don't think so, it's the bias added specifically to the atomic_long_t
that's the issue with the percpu refs.

-- 
Jens Axboe

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1019eec3-3b1c-42b4-9649-65f58284bfec%40kernel.dk.
