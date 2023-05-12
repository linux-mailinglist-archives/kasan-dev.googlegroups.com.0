Return-Path: <kasan-dev+bncBCT4XGV33UIBBSFB7ORAMGQEFBRI2VA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id B1B0670129E
	for <lists+kasan-dev@lfdr.de>; Sat, 13 May 2023 01:50:34 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-1ab0a30ca0dsf62408405ad.3
        for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 16:50:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683935433; cv=pass;
        d=google.com; s=arc-20160816;
        b=aDcRO1KTSB6qn4STxSoBottuUzLoXQgRE9zwgdhuR6Tz8T6ItKj88GJYBryTPQWztu
         DCZbleKAcAkPKnTQVvM9zgNLK2OQ5C/iQeQo66OpPOzIzfvGhsDfjYvIAycRocw5InGG
         nJzFMX0XLlKIkiv5jmN1tB0tEe0OlwpCo0wahe5otmGmK/EeRqJ1qcc1O/Kicn6xgFXB
         pvmcn+PEjBvTaxQea2aezvwIlBNTo2Ti65nbi+XiZW64pfmBMnOK5A5NwK+gWfZq5UjL
         sQYolI4rp0W/+3X1QY1qgXjOemHKhDz61DK1oeIGRIaRxWoZ5lRmzQq3Kap576ey8sAN
         fyIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=eovXUDo1wz2QnNQSL/LeqgBm7hs0MAb7Yq9L34zcYCc=;
        b=0FXRgh6rrWEC34s6kkPtsfgaE0C7H/7KHehli1otTK2K1EqeIDkQGx8bJIDCy7krmr
         X6ZNATzhnJQ6f5UCYpbEonAxtTDIIRIXX3DrxykXZpnKSeIOYBDAZQxZgSg/nggh8ERE
         GKPuamPD/xv74t9NeOv7beayASTvyKpymsDajkfr28uZR7uma93J5xtIl7Yl1fKVde9Z
         mNQj8QAN7AKsKHh6vDFdFfLiYLuTlIdX3HQTSnexP2gUDaWFjznM9Bh590hwGiQjzcqp
         d+PfoyNedRIMopH091rCwi1nHDei144Wk8Z+9lViQH6rY15AYAqK1J020jmmfkUOQ0Vw
         YdYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=vvA0DDvR;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683935433; x=1686527433;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eovXUDo1wz2QnNQSL/LeqgBm7hs0MAb7Yq9L34zcYCc=;
        b=FGNCRd7Rswz+m/eZp9Jacr3M2NHraN6KuPswEQJ/NMRLD1sZXDVtrBWJEIbSKbpCFe
         E+pshZJhLU5HxBK2i8jxoVk7WkMEBNrVBOEAMTogElcuLXJT29Qs6+EiKctX95qBmX0A
         00+Zk+rgNKfIE+UIGHlUbZLKoZ/rKiM92QcV1A0Mcc3gvWdGBLNOeKzQOn8QxMfRqoGQ
         /G3NboVCcg/a155eLNM7NAmcj3Mz1YZX72boulZyc3CxQkM3s7Z4yO9sSORIF1adfuVF
         E/jUpae3GPz9VmtO4ssIUVa4sJcA+ikv9Xcb1cD05+eltbOM7AI2PJZCLm8LGXfwF/Ty
         HDbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683935433; x=1686527433;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=eovXUDo1wz2QnNQSL/LeqgBm7hs0MAb7Yq9L34zcYCc=;
        b=MtlxIsAN6EsRdjVIXGWWP1ggWr6KSFl0kYdULMdxmbwQmMv2Urg+rjzjR8YjZzyFh2
         kvEK69kM8unXRv0QH1pYjMZZ2E+k+Ef3+sCNbGqkaCYBnWTiBkCqLQCUs0nyS51Yolxw
         ErpH8gsvDNOdd0m6Id9pmpHg4yElfM+IrfsIUgyfz5d3afgbql+0eEBnJ0UBrG5bYeNR
         S37FQ/gX2+tU5LMqL4CAUFgCTUnXL7ZOIh2j6XOrhZtMZQpNQ97yu33zBHjqk5DsR/Yi
         b3ptg3OjPVYwQ7ij64M8xKY5tTxRwjmMRdWlrg2wFCOnTfUFx+ub4d8lpV+3hgRomiV1
         DdOw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDzVX69UyYotxqY88tGZR4Y6lKNTnYfVCe0qTxGdZkNf1zhTcQSU
	Pz4bm1qg/GGv/70Jx6Hxj6Y=
X-Google-Smtp-Source: ACHHUZ4PJssENLLeJNyfSu6aifTTJCm5JrXW+q5t3/sy9K56PBvKzaU1AQNTTLNBS66aM+96VdI96g==
X-Received: by 2002:a17:902:7781:b0:1ab:16e6:7aa7 with SMTP id o1-20020a170902778100b001ab16e67aa7mr8402588pll.0.1683935432877;
        Fri, 12 May 2023 16:50:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:588f:b0:24d:f0d1:e44c with SMTP id
 j15-20020a17090a588f00b0024df0d1e44cls5926616pji.3.-pod-canary-gmail; Fri, 12
 May 2023 16:50:32 -0700 (PDT)
X-Received: by 2002:a17:90b:1c8b:b0:233:fb7d:845a with SMTP id oo11-20020a17090b1c8b00b00233fb7d845amr27774233pjb.4.1683935431910;
        Fri, 12 May 2023 16:50:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683935431; cv=none;
        d=google.com; s=arc-20160816;
        b=s3O65hYjFN+93DL2lnuFxw6G10FViE9Bc9DIzVj70W09368+ACApOpdlGLkGc7T0AB
         G11M5xTy1FGwOJFv9Pzui8GrsEv7D6o5NmTxJB9m/OrziKxtb5Yx0fFJxr6+/XnW0rxm
         akE/1TR21fJi3Kt6TJX49lt0Sd28sBlQaVc8CA85tPTJz8YJEn+3ihTyy7dKAe2RUZzW
         UQzMjKenUDVMupLP2b4pR7G5s7s1f2meMlSmcMDMoxeo3IcYCy8efU2s7OKW1sP6Z6j6
         SqvFmVzOpC37qm7JYq/QI5d0+YrKE6yJECWUHpnSyLMZy3C+IJQuRFV6mOt6r+W8qX2c
         +j7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=CmZwRW9f3OkmJ3J6oFz9Yy90YFhs9WiHIfu+zWwKvsg=;
        b=ZTHgAP5KcmeMSIUbXMmWEhQawIs2EfoZ3uAHa4ZYM5LxB6lFloU8d72Pjv27qAD5ax
         bctcVwWDz5FK1Ls3R8DCYcvQImBcVQ6KXpyDnhZDpqc88/9pOoz/Hn+2r8qOwlaU6AP0
         ELk0WXcfXG/3DQNJGM05YAJvFKfbqxDILKFFtvRgm0+9Kp2Xp/Dn8i6CzOMOw2Em8eLN
         LOHbnbEighmNvBPcC+UzT4o95Vfm6u7UXff+cSScS62ucCzCTXCf7KVSi9wkrQwVZCOQ
         OeovcfMl0pLEZNsG4H86F4SYUbgpS1omi2/5/LuQMEE5LJGdEY4DQe4KVES8z67XtSrS
         Rcvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=vvA0DDvR;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id g9-20020a17090ace8900b0024790d8421dsi1484937pju.1.2023.05.12.16.50.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 12 May 2023 16:50:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 54ADF611DA;
	Fri, 12 May 2023 23:50:31 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 435ADC433D2;
	Fri, 12 May 2023 23:50:30 +0000 (UTC)
Date: Fri, 12 May 2023 16:50:29 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Arnd Bergmann <arnd@kernel.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Arnd Bergmann <arnd@arndb.de>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Alexander Potapenko <glider@google.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo
 Frascino <vincenzo.frascino@arm.com>, Mark Rutland <mark.rutland@arm.com>,
 Mark Brown <broonie@kernel.org>, linux-arm-kernel@lists.infradead.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-mm@kvack.org
Subject: Re: [PATCH 2/2] [v3] kasan: use internal prototypes matching gcc-13
 builtins
Message-Id: <20230512165029.9ce044570a2906e7185fe38c@linux-foundation.org>
In-Reply-To: <20230509145735.9263-2-arnd@kernel.org>
References: <20230509145735.9263-1-arnd@kernel.org>
	<20230509145735.9263-2-arnd@kernel.org>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=vvA0DDvR;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue,  9 May 2023 16:57:21 +0200 Arnd Bergmann <arnd@kernel.org> wrote:

> gcc-13 warns about function definitions for builtin interfaces
> that have a different prototype, e.g.:
> 
> In file included from kasan_test.c:31:
> kasan.h:574:6: error: conflicting types for built-in function '__asan_register_globals'; expected 'void(void *, long int)' [-Werror=builtin-declaration-mismatch]
>   574 | void __asan_register_globals(struct kasan_global *globals, size_t size);
> kasan.h:577:6: error: conflicting types for built-in function '__asan_alloca_poison'; expected 'void(void *, long int)' [-Werror=builtin-declaration-mismatch]
>   577 | void __asan_alloca_poison(unsigned long addr, size_t size);
> kasan.h:580:6: error: conflicting types for built-in function '__asan_load1'; expected 'void(void *)' [-Werror=builtin-declaration-mismatch]
>   580 | void __asan_load1(unsigned long addr);
> kasan.h:581:6: error: conflicting types for built-in function '__asan_store1'; expected 'void(void *)' [-Werror=builtin-declaration-mismatch]
>   581 | void __asan_store1(unsigned long addr);
> kasan.h:643:6: error: conflicting types for built-in function '__hwasan_tag_memory'; expected 'void(void *, unsigned char,  long int)' [-Werror=builtin-declaration-mismatch]
>   643 | void __hwasan_tag_memory(unsigned long addr, u8 tag, unsigned long size);

I added cc:stable to these, but staged them for the next merge window.

Because I expect many people will compile earlier kernels many times
with gcc-13 and later, and they won't want to have to see these
warnings all the time.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230512165029.9ce044570a2906e7185fe38c%40linux-foundation.org.
