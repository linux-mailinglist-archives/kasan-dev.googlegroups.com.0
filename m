Return-Path: <kasan-dev+bncBCOJLJOJ7AARBOVJUSUQMGQEHQPJXIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 204D37C82A5
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Oct 2023 11:58:21 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-2c12bb1f751sf19186261fa.2
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Oct 2023 02:58:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697191100; cv=pass;
        d=google.com; s=arc-20160816;
        b=yPI4kjNxbnqFBU5QnvtgAIviD1RFFYOneKsRD5VNo5KHEr8u/ME7Tz1pTOW4WK3ede
         HS5ArpLKE8Mt0cfLoxU//soQqhtxczyDudHmnC3/iiscakADFIaFGhYqcULuJIuPPHjg
         WDsBLSkeGVdfBbom3nY722cWm4oNOaSY/UVRbL88a8sNfb/A4UXKl0gx3tf+cxp67KJp
         d7WQZhYQX1fgq/vAw9trjNwlQdv/2gVhGvxKsEtI7Z2EM9++8I9frhrya/Z2h+57TuTB
         /Xwo6976KmzoIjuj9X7N1BwE5HEfnGaGVJc+xhNy/h0E9k28tKwNcU/rq2EA20SjS3ae
         QoNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Zdryte7V5a9TmjNAxwCBYQ/7yeiRLckkWEFQJdp94zU=;
        fh=1jGKVQzSoQG5CwpLF44A+EBM6uiLcZqcj4Yd2gyN6+k=;
        b=MncQ6CmLzOinPcF5Nhq3jbUkycWdiPo2uZQLO7G0giEp9XA8BhQ2K1aKCYXdAgyrJK
         FsC1AhaPMO6ea2MLlH9GdLBmqFasOvZ601/tXDYyry+dCCVpRPtl7/YmxddqcefPhAWU
         5XifukgXmASb74bA9D4/fzi43qFcQfgI1+2NZg/IDXOYTVDcPWv+g92CGnGIQ7zdM6tB
         O9roz0XfQ88zKezvDA2KU0fkfq1btCWg3U/6czlQAdl9ewBdSXNOMT3ZR9L8TE10Cw5k
         zarpW+e1W/F89RIv3DCw7a5lBSvnSzEkpwIYToJJTKIUk8mcpDa/0MnZFBXT+vM2PFIN
         ax5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ventanamicro.com header.s=google header.b=HCg1tWod;
       spf=pass (google.com: domain of ajones@ventanamicro.com designates 2a00:1450:4864:20::534 as permitted sender) smtp.mailfrom=ajones@ventanamicro.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697191100; x=1697795900; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Zdryte7V5a9TmjNAxwCBYQ/7yeiRLckkWEFQJdp94zU=;
        b=UzasBspM5roCWN5ngjV+hl0VcjBFeTPG8oi0OOfGqHksaZDKgjsfKbTeixjvQAY/F/
         MNZQ5JkX7r4FEvePOXmDCEU6dPheO1eE3Ov1Ib8kAvi1j8v/boNFPPBmtd2nRBte0yza
         15vwHvWw2DH6OGZ6eZivLTm2+xNOewr6lmUwG3mQ0pxMo3VMrHdJ7IpckL6utTvMhXvh
         Mu5A32WAM0mjYHx9nHBMmXcc36d3TDSNatR/D8K6zeW/L2YRpMgcr95+tIHawMl4BdYG
         ecOfn7kcoO/eLPkjAn5j+NgGyPFr40mA2yTg3p+lv1o5KhxvkS6PtGpWK7PrLTz3K+xs
         JeDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697191100; x=1697795900;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Zdryte7V5a9TmjNAxwCBYQ/7yeiRLckkWEFQJdp94zU=;
        b=YEbLtTDzumblHo43g29HtkOHNysW8Mc2OZ4n9aKJOAq2lvHlKmbSB7yz1HmoFdsbSA
         vZnpKaM1ioJfpOzO94+YF/+6hB17gFOCn4/QIM+azpVifMPH+/W2dUn7ansmYbCPOtI6
         fjRBCzT1z0TJzVn+20Vxkc3zbJttCyfQodW4kluWw/2xEThBQk80R4r2gm887Jy5SSSz
         CSeXFX3SUe743rY9K0f3Y84Te7drS6j3APZSqk9+xHcP+MXeB+ohhzGuOhwmAufzUKTc
         Bd6Y23g+g0qOprx71CzygkQYk452znx/zUwZQwyL4xLl6treWJ8jzT9O1QYIUqSZxkUW
         lZlw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyAVtN9zay7L3GiawKNzFNXHoQ7KUfADBK/DTNpQLYfpCRxHlD3
	JGpD7oBviCEh84JpD2AGIDk=
X-Google-Smtp-Source: AGHT+IHzKfiTjfZsILsTu3g6Q1VYjFfV3H7pC31OyvEvBcYFFUgVKrtf7QeGhgq8rwa10O3VLB0aBw==
X-Received: by 2002:ac2:5287:0:b0:503:3447:b704 with SMTP id q7-20020ac25287000000b005033447b704mr2038941lfm.0.1697191098946;
        Fri, 13 Oct 2023 02:58:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2313:b0:507:9d16:db with SMTP id
 o19-20020a056512231300b005079d1600dbls178238lfu.2.-pod-prod-04-eu; Fri, 13
 Oct 2023 02:58:17 -0700 (PDT)
X-Received: by 2002:a2e:848a:0:b0:2b9:f27f:e491 with SMTP id b10-20020a2e848a000000b002b9f27fe491mr21162612ljh.42.1697191097013;
        Fri, 13 Oct 2023 02:58:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697191096; cv=none;
        d=google.com; s=arc-20160816;
        b=mXW5m5u+XB0RJdGXmBNB9vOBYPSaPPrVf9VkfUtBct28IQ1H4dtDhR6Kg8QSe9rAZ1
         I1a9C+VI2HatDCR65dMMZ24i3+9r9J8mL4X2JXg2ymUXErmV2Jg77I1UFFJx9+aYCpmk
         56s/wSM7S2wxOXOV9wW5Vg/TQxa0QoBLkkKwLx0P49z2ENDBxre68pyIThRA14irFUmE
         /fuLE/GgrIqvqXl4Xio3J9oo+kvOf2m5WhHRDEtGs1EFqlsB/4evbRuYcZ+IrwzTlAJQ
         zBK8EZDs7+wfC/745WM5w28NovmKNqDBNDqmUzvM+vIHuDSzwDcBKaN4opThybDS7/N7
         l+TQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=nlysa/0HAt7XwTL7Sd4FpaqX2JsJYLCn7DORbQofqo8=;
        fh=1jGKVQzSoQG5CwpLF44A+EBM6uiLcZqcj4Yd2gyN6+k=;
        b=dXnH7E9t+0QNsh5uE9MQm+Eu1/E2dMSgoCF220BMaIhzx5zCfRClifB/R//MfI0HSg
         2dJibUnO6jBkx6dEIikVFy6NBlX+kkYiyG0fmxTkeVWy9smlNhoKPacICkQfum/0xLaj
         Y0NEPN617bTGRTTZB47+R15sm5XFlGx82WxEqpSRZ/OcvfyMNtH2Gy6emayOd+IUP+YY
         2HwQt9HlY4wSTQFD2IKNb1UG8SYJGYfKDflX+F4D2yH9GzwfcCnfV11kMS75VSLNbe5r
         TwQIKcVKFCBIuIdST4R1qR5JsUVG2/pxTymwqh2YkcRgOe/WMsNnSNoYpcPOKq5h4iv8
         ERNA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ventanamicro.com header.s=google header.b=HCg1tWod;
       spf=pass (google.com: domain of ajones@ventanamicro.com designates 2a00:1450:4864:20::534 as permitted sender) smtp.mailfrom=ajones@ventanamicro.com
Received: from mail-ed1-x534.google.com (mail-ed1-x534.google.com. [2a00:1450:4864:20::534])
        by gmr-mx.google.com with ESMTPS id e16-20020a05651c151000b002bced4ef910si1097274ljf.3.2023.10.13.02.58.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Oct 2023 02:58:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of ajones@ventanamicro.com designates 2a00:1450:4864:20::534 as permitted sender) client-ip=2a00:1450:4864:20::534;
Received: by mail-ed1-x534.google.com with SMTP id 4fb4d7f45d1cf-53df747cfe5so3533238a12.2
        for <kasan-dev@googlegroups.com>; Fri, 13 Oct 2023 02:58:16 -0700 (PDT)
X-Received: by 2002:aa7:c998:0:b0:530:a226:1f25 with SMTP id c24-20020aa7c998000000b00530a2261f25mr21443281edt.17.1697191096257;
        Fri, 13 Oct 2023 02:58:16 -0700 (PDT)
Received: from localhost (cst2-173-16.cust.vodafone.cz. [31.30.173.16])
        by smtp.gmail.com with ESMTPSA id u19-20020a50d513000000b0053e408aec8bsm650498edi.6.2023.10.13.02.58.15
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 13 Oct 2023 02:58:15 -0700 (PDT)
Date: Fri, 13 Oct 2023 11:58:14 +0200
From: Andrew Jones <ajones@ventanamicro.com>
To: Conor Dooley <conor@kernel.org>
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>, 
	Ryan Roberts <ryan.roberts@arm.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Anup Patel <anup@brainfault.org>, 
	Atish Patra <atishp@atishpatra.org>, Ard Biesheuvel <ardb@kernel.org>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, linux-riscv@lists.infradead.org, 
	linux-kernel@vger.kernel.org, kvm@vger.kernel.org, kvm-riscv@lists.infradead.org, 
	linux-efi@vger.kernel.org, linux-mm@kvack.org
Subject: Re: [PATCH 4/5] riscv: Suffix all page table entry pointers with 'p'
Message-ID: <20231013-19d487ddc6b6efd6d6f62f88@orel>
References: <20231002151031.110551-1-alexghiti@rivosinc.com>
 <20231002151031.110551-5-alexghiti@rivosinc.com>
 <20231012-envision-grooving-e6e0461099f1@spud>
 <20231012-exclusion-moaner-d26780f9eb00@spud>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231012-exclusion-moaner-d26780f9eb00@spud>
X-Original-Sender: ajones@ventanamicro.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ventanamicro.com header.s=google header.b=HCg1tWod;       spf=pass
 (google.com: domain of ajones@ventanamicro.com designates 2a00:1450:4864:20::534
 as permitted sender) smtp.mailfrom=ajones@ventanamicro.com
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

On Thu, Oct 12, 2023 at 12:35:00PM +0100, Conor Dooley wrote:
> On Thu, Oct 12, 2023 at 12:33:15PM +0100, Conor Dooley wrote:
> > Hey Alex,
> > 
> > On Mon, Oct 02, 2023 at 05:10:30PM +0200, Alexandre Ghiti wrote:
> > > That makes it more clear what the underlying type is, no functional
> > > changes intended.
> > 
> > Scanning through stuff on patchwork, this really doesn't seem worth the
> > churn. I thought this sort of Hungarian notation-esque stuff was a
> > relic of a time before I could read & our docs even go as far as to
> 
> s/go/went/, I see the language got changed in more recent releases of
> the kernel!

The documentation seems to still be against it, but, despite that and
the two very valid points raised by Marco (backporting and git-blame),
I think ptep is special and I'm mostly in favor of this change. We may
not need to s/r every instance, but certainly functions which need to
refer to both the pte and the ptep representations of entries becomes
more clear when using the 'p' convention (and then it's nice to have
ptep used everywhere else too for consistency...)

Anyway, just my 2 cents.

Thanks,
drew

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231013-19d487ddc6b6efd6d6f62f88%40orel.
