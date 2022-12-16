Return-Path: <kasan-dev+bncBCCMH5WKTMGRBVFI6KOAMGQE3WCBGSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id A40D864EE34
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Dec 2022 16:52:53 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id j5-20020a5d9d05000000b006e2f0c28177sf1512190ioj.17
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Dec 2022 07:52:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1671205972; cv=pass;
        d=google.com; s=arc-20160816;
        b=NmHPlu9G+BVD6DkeUWgLvI23LGSeMMdl9LH86aqtl6E78pH9pXUWi9XmhzbR/fr9W8
         WIqeD5J14v6FzIGVcJxOEGB6wuGUeO7j1fKbfVKyyQYBDL8jCIysXQaYTQRJ9k4jXAWL
         pjSZtyNR1U4DGnQDYJICJuIKK4Ukdrn7SzixP1gRl3YRjJyR9CYQ+HWWMk3YmBzpQHxw
         umHx1czLkhCeLUptRTb3smZFLxMPRE7Gn3XVKtmDPugmHGC8FI+YeumS3dhsF1edkE3k
         miHUQwyrDQBbFz5P3Un8kOVh76U7oiQJzlHYt8K/9yuTM2u+iZikv+0bErxnWboISaUC
         zlyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IXcAzl4Zqi4GYGsrtbiNcAlLtpg6rZKqcqVZvr0Lpsg=;
        b=C/BM1h4NoUsz3QoWGPYO7YZK955TeJ+hFkZmeTNIBzTscx6x7wsyB7uBuHTA+uF9bT
         wLQe0Ztli9GI4NMJCiA6fn4qhM7U4mLmit54HJ4bOe0jfW9zxxz5TMVltsYXYPZqyBDA
         dVMCkCALMST+KXu02jHNq3gdlrdj5VsJ0B3O/DDXu5TPs/hWF3xMsoR/a2yDU+m10Z1m
         nM8HLZH68hTjXu63h1PdtXXjUAPQiQ48k6LJWE+xDGxt+TlwwYKHmj70PwYuGjMwt46J
         1rWVbuEVCso9f3HRa4tBFzDcgwVRpozBLYRwJgMON6gYtkcQHdKiUUmJmh/V70NqBvZP
         LcKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=MKvZJHiN;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=IXcAzl4Zqi4GYGsrtbiNcAlLtpg6rZKqcqVZvr0Lpsg=;
        b=Ppp5Sk5mAc8KnQBXPJIu3k8xONtNwuVRrxAtUnHAOnu3F1g4vevMihVyn0ERT3r5Qs
         U1AoOGaCT8M8Hn8DkXypcCz6cmHB+xhJHLkPlIA89q1TA5eQErMUX+NqDQdslF/n4Wfq
         0H2BNTQiiG3alluDKmvFJSghwasIf50h2dFeunCfJzyWSyyL8rBPgM0QHabRQ/e0hIjS
         muHrtp3iWp+I8fUaP3RwDjr6GV+AQs0MRkII9m28uifsEGsJtKqpji4ysQbU5eRH5i+a
         q2kK5iDG1bGAwYBWI6CTMck5tMqftZXr+V9SBIyQbaucdnqgD3oCRiXnOirx9QBBLfGz
         OqYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=IXcAzl4Zqi4GYGsrtbiNcAlLtpg6rZKqcqVZvr0Lpsg=;
        b=ClNvRccjNYDW7GFqVuyLovRlDhdo59Rk5gZqeQz8MOmeo2cCuU/wUz4rjhENev1wlS
         oIR50Oxe0eom7zWtR3wTetJnFGLOwhD5ftsOpavZ45fi/oyetvEcj+5b10oKuhgaJ2+7
         VV7MGY1n10fjvFef5Zs1bpVtFeRq240PaM0Io/GfMwbFMI0TRVkI1At/ZydLq1uquk+F
         QcS92r0KwIbAwHsCGoU7+OkLcnqtMoj2ZZpZ2QGe0lGH3ehEcS57x1wuwzKuPuoxrOFo
         jk6Hcu1is9SV1Ubgs+96tiyAWaw2ugyeMVSH18zHr4qU4Whp2NTjZ6HPdsWrPai6MW0E
         6deQ==
X-Gm-Message-State: ANoB5pkLlyry6iZynUoHxPWCouFHxv0aEUGhEmjc79542zmHxBZwhElK
	5zjKEH7YDVzIH1EaeyPBeFo=
X-Google-Smtp-Source: AA0mqf49MQIuzMX1DzVilJ7+uyK07LERbsj2HfYaPa9cfTLfoVy2Xom7wpx7gUwUwohVhL2TjKDM3A==
X-Received: by 2002:a05:6602:2818:b0:6db:6628:d30b with SMTP id d24-20020a056602281800b006db6628d30bmr36678331ioe.178.1671205972437;
        Fri, 16 Dec 2022 07:52:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c7ce:0:b0:300:dcf8:8fc8 with SMTP id g14-20020a92c7ce000000b00300dcf88fc8ls648076ilk.10.-pod-prod-gmail;
 Fri, 16 Dec 2022 07:52:52 -0800 (PST)
X-Received: by 2002:a05:6e02:1524:b0:305:e07f:e7a2 with SMTP id i4-20020a056e02152400b00305e07fe7a2mr7697803ilu.6.1671205971965;
        Fri, 16 Dec 2022 07:52:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1671205971; cv=none;
        d=google.com; s=arc-20160816;
        b=WZp/5bRmIcKhDRKfAqdBZv3AaSlyXChN2cfOnE2tji7AB9/TMprhE88XQK/6MqBVsR
         xDQ89cUo+KKsRwv7CjTqi6HUZyLjo8YgQzwIXqy4NeZrtGaPcXH+FTtJtmgMCOkp1/uu
         AHYIRFaogq2ChuifoNORZlJ4bZj1Us8ym4aHHP/AUfHlX7H6aQrwwGxr5n6sPjZaP64Z
         /ZcounuJ0fbglkiEedJLVfx2oNuhwAASIE+Nhpsyx3sllPeeSh5X2f0/Z0czei5bi7/D
         4DvD+BvpyI3iLgZzJuTnFhaiawjtGKdNhMjwS9vqMCI+lZns3jzfMawl1lxM1QeCmfgD
         TbSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=UOP93QaAQMcfYeKQh80Wnem5s5Ji+Q2nkQ3zFddX4zk=;
        b=zP085OA0ps7DEkZOf7fxbPeF+mhtTYlS2KELcxkuQZ3yyxllZD/BAS7PmQH9sTCpx5
         DDHxgy5oWUmEKUGg+ECPTti3oDV9zJbnY/aAZ4MSnqfPphKVNr3iHAYIQkmeoPGqSNOK
         k/70i2TzjdLNDTZ7nBm5hy6xsXD1DUWkWwUv9Qg6yUur39zzsiJ+gKBnFdJ6g5SdDwoT
         +3f0oBu4ZfS8RK+tmwNCDo+WNqa/Acm03UyVr6OaKSzCy7UftcUu+YrLQuL4l7r8O0cM
         Cs8Vculwc8jqACnzBCmM3z8sCF8v3FjYmT2A/NurWmJZx+MDFxZPcQf1VfrzfNI3A3bu
         lbXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=MKvZJHiN;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1131.google.com (mail-yw1-x1131.google.com. [2607:f8b0:4864:20::1131])
        by gmr-mx.google.com with ESMTPS id n2-20020a02a902000000b0038a6bbe1e21si190718jam.1.2022.12.16.07.52.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Dec 2022 07:52:51 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) client-ip=2607:f8b0:4864:20::1131;
Received: by mail-yw1-x1131.google.com with SMTP id 00721157ae682-3b10392c064so39284537b3.0
        for <kasan-dev@googlegroups.com>; Fri, 16 Dec 2022 07:52:51 -0800 (PST)
X-Received: by 2002:a0d:f781:0:b0:373:6e8a:e7db with SMTP id
 h123-20020a0df781000000b003736e8ae7dbmr9775062ywf.144.1671205971474; Fri, 16
 Dec 2022 07:52:51 -0800 (PST)
MIME-Version: 1.0
References: <cad03d25-0ea0-32c4-8173-fd1895314bce@I-love.SAKURA.ne.jp>
 <CAMuHMdUH4CU9EfoirSxjivg08FDimtstn7hizemzyQzYeq6b6g@mail.gmail.com> <86bdfea2-7125-2e54-c2c0-920f28ff80ce@I-love.SAKURA.ne.jp>
In-Reply-To: <86bdfea2-7125-2e54-c2c0-920f28ff80ce@I-love.SAKURA.ne.jp>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 16 Dec 2022 16:52:14 +0100
Message-ID: <CAG_fn=VJrJDNSea6DksLt5uBe_sDu0+8Ofg+ifscOyDdMKj3XQ@mail.gmail.com>
Subject: Re: [PATCH] fbcon: Use kzalloc() in fbcon_prepare_logo()
To: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Cc: Geert Uytterhoeven <geert@linux-m68k.org>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Daniel Vetter <daniel@ffwll.ch>, Helge Deller <deller@gmx.de>, 
	Linux Fbdev development list <linux-fbdev@vger.kernel.org>, DRI <dri-devel@lists.freedesktop.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=MKvZJHiN;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1131
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

On Fri, Dec 16, 2022 at 3:03 PM Tetsuo Handa
<penguin-kernel@i-love.sakura.ne.jp> wrote:
>
> On 2022/12/15 18:36, Geert Uytterhoeven wrote:
> > The next line is:
> >
> >         scr_memsetw(save, erase, array3_size(logo_lines, new_cols, 2));
> >
> > So how can this turn out to be uninitialized later below?
> >
> >         scr_memcpyw(q, save, array3_size(logo_lines, new_cols, 2));
> >
> > What am I missing?
>
> Good catch. It turned out that this was a KMSAN problem (i.e. a false pos=
itive report).
>
> On x86_64, scr_memsetw() is implemented as
>
>         static inline void scr_memsetw(u16 *s, u16 c, unsigned int count)
>         {
>                 memset16(s, c, count / 2);
>         }
>
> and memset16() is implemented as
>
>         static inline void *memset16(uint16_t *s, uint16_t v, size_t n)
>         {
>                 long d0, d1;
>                 asm volatile("rep\n\t"
>                              "stosw"
>                              : "=3D&c" (d0), "=3D&D" (d1)
>                              : "a" (v), "1" (s), "0" (n)
>                              : "memory");
>                 return s;
>         }
>
> . Plain memset() in arch/x86/include/asm/string_64.h is redirected to __m=
san_memset()
> but memsetXX() are not redirected to __msan_memsetXX(). That is, memory i=
nitialization
> via memsetXX() results in KMSAN's shadow memory being not updated.
>
> KMSAN folks, how should we fix this problem?
> Redirect assembly-implemented memset16(size) to memset(size*2) if KMSAN i=
s enabled?
>

I think the easiest way to fix it would be disable memsetXX asm
implementations by something like:

---------------------------------------------------------------------------=
----------------------
diff --git a/arch/x86/include/asm/string_64.h b/arch/x86/include/asm/string=
_64.h
index 888731ccf1f67..5fb330150a7d1 100644
--- a/arch/x86/include/asm/string_64.h
+++ b/arch/x86/include/asm/string_64.h
@@ -33,6 +33,7 @@ void *memset(void *s, int c, size_t n);
 #endif
 void *__memset(void *s, int c, size_t n);

+#if !defined(__SANITIZE_MEMORY__)
 #define __HAVE_ARCH_MEMSET16
 static inline void *memset16(uint16_t *s, uint16_t v, size_t n)
 {
@@ -68,6 +69,7 @@ static inline void *memset64(uint64_t *s, uint64_t
v, size_t n)
                     : "memory");
        return s;
 }
+#endif

 #define __HAVE_ARCH_MEMMOVE
 #if defined(__SANITIZE_MEMORY__) && defined(__NO_FORTIFY)
---------------------------------------------------------------------------=
----------------------

This way we'll just pick the existing C implementations instead of
reinventing them.


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVJrJDNSea6DksLt5uBe_sDu0%2B8Ofg%2BifscOyDdMKj3XQ%40mail.=
gmail.com.
