Return-Path: <kasan-dev+bncBCAIHYNQQ4IRBHUPYLAQMGQEPO5IKVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id F24ECAC2516
	for <lists+kasan-dev@lfdr.de>; Fri, 23 May 2025 16:35:11 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-2d572363154sf31089fac.0
        for <lists+kasan-dev@lfdr.de>; Fri, 23 May 2025 07:35:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1748010910; cv=pass;
        d=google.com; s=arc-20240605;
        b=OMEgr91yBfja2lMydGXPh+kkjfOY8oPNkxgJtLRZOc1udvnFTBuAzB3xAfS3Q1QT40
         pEK0TMiVSG17LcE4dt5mA6QFMC2VFymBxmq6Pg/ozMjiZAnPLrO80ryvkJI9f+vQczDJ
         FR5wt6qIeI8NHjR0nSvZeRL+vpqbuCkasDumUS8a3rRCR5Y3OtzDbFWNEEsu62sxfagw
         JL/IAiCFRyY+3C2+Il++rY2nQXJkc2IxGpABj6XI4FSjvQkmZtVRQzzgtXK5zF5+qkDb
         rCoB8OKTE4nhsu5HEI866SCoxtVDYHDRmsnY9nqxKWvIYMexdcK5d+PxEq6/3tPlegyv
         B6mA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=z/Bn/fnMBHmg4XM1+jAQNf3Jd/TgkJT8Sk9ApS/Sqvo=;
        fh=k2hEZb0jBxa7CdHquLqYyE25JnTL25wAFdnYXAjevGI=;
        b=ZgdowHf7v9ge6r48i8mKJrqi7NLOfNp7UelaVEruh3s0YzDZR0ZXMX0XxqJumHO+vQ
         /y/BpG2iJ7UpjWB85YFxnjMYa8yVgQsODRT+5NvUXR6NUuR4fLxxxwuDab7SvZX4PIGh
         3jWGOO4kvmU+ZJxDcJGs9DRKonQea4tnE8XaxPVZrr/5/LDBiawzYguCgSmEPjpw/7/X
         SYXsnK3kAdcAXCfIkka31QBEs9iz8TIass/8U2+q1GHHTNqocoJlEI2xHpgz2xdEqkVn
         l9iA/hUR1OGo1V5nuATnVh8aaPzmyS5kLsrhDL7VkthuTS56JbzROFElFpMMbe2+ooI9
         HDUw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=SltP1Zkq;
       spf=pass (google.com: domain of 3nicwaaykcbunzviexbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::649 as permitted sender) smtp.mailfrom=3nIcwaAYKCbUnZVieXbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--seanjc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1748010910; x=1748615710; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=z/Bn/fnMBHmg4XM1+jAQNf3Jd/TgkJT8Sk9ApS/Sqvo=;
        b=aWLPGd9KODmHJdhulhjLkvnyc1JdaIN2QBut/CREhRlGDpxK0acpt+lXt2NE5xSuT2
         BjXfTe1/U/odjkcPg7tGknTRrQyPzYEaBGZf2ZLBbjKC+MHojvBdvuIR+tBDgPUciscu
         IJO80seJFD6fv8N+4W5FY/QdqL04UTrUdyeR47u1Xaybo4slCeVBaHT1ncE8DwvRDMrc
         gxQ3jxx7E78Qyu0hNfDLGAM3RwtnkHHOmPxO+RWOOH2yQlOrCMhEc062zbaoZtDuNweV
         QLtWnHcHFJfis6QD5eKqYjZoUYX2hxx4B0D6aXtEqOQIJ85TjEdLEhmrt8X7UbPyQ59j
         yxyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1748010910; x=1748615710;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=z/Bn/fnMBHmg4XM1+jAQNf3Jd/TgkJT8Sk9ApS/Sqvo=;
        b=VHYQe1q1gHQowqNKBJ29dePLARnkzD/fM4DQkBgQnQN8jKscD9LqSD/vL+80mrkwE3
         v0hZ7WHqLbtBt2pAdK2SErVynQqqQZDZE//Tvg5tL3zH0EvornI8YdnCzQSFeAM0k6a7
         s7DuPmbMycoh8AKCtJWKyx06NPZDkIF0pzHTnRzsQxMv1s5wb5tdnEU/M8o5944upODe
         GqeEDvZS9yT+8+jSMcHIah42b8xGMIaKfpLFSLgcQYwt8RPMKhtdttKiMcC1cvmvUi67
         1kjrvX7PTC3ilpsSQpOcW3/RBfiy7F5KzG1fEE3fM67uOQrVXzJSSrbIOsTNipHbKHOU
         MJiQ==
X-Forwarded-Encrypted: i=2; AJvYcCUhJXnEDrTevsKD0FZg3xNihedPRZonXQRRzxwWFdETNzN6DJRBxqFhvQxmBkissoIBOxgktQ==@lfdr.de
X-Gm-Message-State: AOJu0YwcQag53ECF7Wvbnn6zF1fGGM83xX7xBreBD221wX4HUe+u2uNY
	aSCPXYdbdQM2/oBprSIMrSVdQbMozT6ZLtoYv3PMNgOeotVt93MrLpfE
X-Google-Smtp-Source: AGHT+IHI23VOxluDKUAoqMdAUylRtlLmupEVRuKkYCg1sLiKz80RlmNi5QjPiVD1ALrUzg+bNnWcuQ==
X-Received: by 2002:a05:6870:9e08:b0:2c8:5db8:f23a with SMTP id 586e51a60fabf-2e844ce3e42mr1936871fac.20.1748010910599;
        Fri, 23 May 2025 07:35:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGPBp9bTTrMFSGGxLbwB1y0gcqqeYEXhYXR8ibt7Sv19Q==
Received: by 2002:a05:6871:20c5:b0:2da:fbc:5e7 with SMTP id
 586e51a60fabf-2e39c84e485ls1201252fac.0.-pod-prod-07-us; Fri, 23 May 2025
 07:35:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWrnYw2Q7dyMtBIvPn7dQFvQaFcqb5cfUPb4/vRenBSZMb4kqrU/uR8JjsZCIzsfOvTk6lb4B+UDGU=@googlegroups.com
X-Received: by 2002:a05:6830:d06:b0:72a:13cf:4aa0 with SMTP id 46e09a7af769-7354d43c840mr2382614a34.15.1748010909654;
        Fri, 23 May 2025 07:35:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1748010909; cv=none;
        d=google.com; s=arc-20240605;
        b=D9uSrexRGPYRjLJrCRhrA3hGmIW1b/DAyNTin4zi35WXe5LrmtdwI2zYdXbwJP8ffw
         m+6IZO7RikYd1HzIdZkUj73yJsSD2JMRYlaTpHtmt/peFBaYgagwygZMASyfb5INPr82
         lO9xdpjBV3jHrwUEiJN/GrWIHeAwa0z+nnyz8i4qYXr5/G/z/JrW8BCFAk5uosz/VaE/
         APoI+J7gPjDs5lwERm6HtM/ZT0ZkXAgArS3jFq9L8iVyQwsCyB8ZGkIgHOFZe56OH3XL
         iMLv4XIaStW9UarUY3+6Y8PlI1GbE4qRkrXT4FQ9CourgUsgXb0BwHSwa/oLqJslzWBX
         EFFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=OHIXFovAEYPRF7pj3DkvXM+Wh6ry7OAZQdb2dc5cgKo=;
        fh=Baeynub6LMuFmVe5etvEeSkB0m+0fOlu4UZV18Y9HCc=;
        b=BD1q7lP5ZbDqxcDZCTv4vjOiK63Zq8L9SKx4CNNNI2EEVyesdLoo/JhMYeLhHGfe5g
         WH32JcbwzCW0f0kr/PJfTb5uFG9vcElkja+Ram6KkHCeYbvudM9pmnAxfkQ5xEUxvkZi
         4Oio2JMF2HFz954UhaXJau83VcwfTJRIKsY4z4sGTOfB9KX9vzpkXnSVVstpO6LwcoNE
         uyvLkPRhK6buaTMjl9PUPx4lvrgOVFKpd0qlLcAlsGEat/ieXnQuOqZisUdi26itEbB1
         AHUddUhn3sjKbMMYHJYPM2HOmqfVVl08p0htPoVeKk2b+KkkYvXeAfyxjCc6byKIROPm
         DXyQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=SltP1Zkq;
       spf=pass (google.com: domain of 3nicwaaykcbunzviexbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::649 as permitted sender) smtp.mailfrom=3nIcwaAYKCbUnZVieXbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--seanjc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x649.google.com (mail-pl1-x649.google.com. [2607:f8b0:4864:20::649])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-734f6a3e497si761557a34.1.2025.05.23.07.35.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 23 May 2025 07:35:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3nicwaaykcbunzviexbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::649 as permitted sender) client-ip=2607:f8b0:4864:20::649;
Received: by mail-pl1-x649.google.com with SMTP id d9443c01a7336-22de54b0b97so88784545ad.2
        for <kasan-dev@googlegroups.com>; Fri, 23 May 2025 07:35:09 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVvdlN0JCazl13GVJawLkmrHnCI74I4/NXpODpM5cZl223g2rmj8Jpwn/dm53iMP1NR8U7eRAHizag=@googlegroups.com
X-Received: from plka13.prod.google.com ([2002:a17:903:f8d:b0:231:def0:d268])
 (user=seanjc job=prod-delivery.src-stubby-dispatcher) by 2002:a17:903:41c7:b0:224:1221:1ab4
 with SMTP id d9443c01a7336-231de317b43mr439457305ad.22.1748010908457; Fri, 23
 May 2025 07:35:08 -0700 (PDT)
Date: Fri, 23 May 2025 07:35:03 -0700
In-Reply-To: <20250523043935.2009972-4-kees@kernel.org>
Mime-Version: 1.0
References: <20250523043251.it.550-kees@kernel.org> <20250523043935.2009972-4-kees@kernel.org>
Message-ID: <aDCHl0RBMgNzGu6j@google.com>
Subject: Re: [PATCH v2 04/14] x86: Handle KCOV __init vs inline mismatches
From: "'Sean Christopherson' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <kees@kernel.org>
Cc: Arnd Bergmann <arnd@arndb.de>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
	Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, Paolo Bonzini <pbonzini@redhat.com>, 
	Vitaly Kuznetsov <vkuznets@redhat.com>, Henrique de Moraes Holschuh <hmh@hmh.eng.br>, 
	Hans de Goede <hdegoede@redhat.com>, 
	"Ilpo =?utf-8?B?SsOkcnZpbmVu?=" <ilpo.jarvinen@linux.intel.com>, "Rafael J. Wysocki" <rafael@kernel.org>, 
	Len Brown <lenb@kernel.org>, Masami Hiramatsu <mhiramat@kernel.org>, Ard Biesheuvel <ardb@kernel.org>, 
	Mike Rapoport <rppt@kernel.org>, Michal Wilczynski <michal.wilczynski@intel.com>, 
	Juergen Gross <jgross@suse.com>, Andy Shevchenko <andriy.shevchenko@linux.intel.com>, 
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>, Roger Pau Monne <roger.pau@citrix.com>, 
	David Woodhouse <dwmw@amazon.co.uk>, Usama Arif <usama.arif@bytedance.com>, 
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>, Thomas Huth <thuth@redhat.com>, Brian Gerst <brgerst@gmail.com>, 
	kvm@vger.kernel.org, ibm-acpi-devel@lists.sourceforge.net, 
	platform-driver-x86@vger.kernel.org, linux-acpi@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, linux-efi@vger.kernel.org, 
	linux-mm@kvack.org, "Gustavo A. R. Silva" <gustavoars@kernel.org>, Christoph Hellwig <hch@lst.de>, 
	Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Masahiro Yamada <masahiroy@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Nicolas Schier <nicolas.schier@linux.dev>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, 
	linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev, 
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org, 
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-security-module@vger.kernel.org, linux-kselftest@vger.kernel.org, 
	sparclinux@vger.kernel.org, llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: seanjc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=SltP1Zkq;       spf=pass
 (google.com: domain of 3nicwaaykcbunzviexbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--seanjc.bounces.google.com
 designates 2607:f8b0:4864:20::649 as permitted sender) smtp.mailfrom=3nIcwaAYKCbUnZVieXbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--seanjc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Sean Christopherson <seanjc@google.com>
Reply-To: Sean Christopherson <seanjc@google.com>
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

On Thu, May 22, 2025, Kees Cook wrote:
> diff --git a/arch/x86/kernel/kvm.c b/arch/x86/kernel/kvm.c
> index 921c1c783bc1..72f13d643fca 100644
> --- a/arch/x86/kernel/kvm.c
> +++ b/arch/x86/kernel/kvm.c
> @@ -420,7 +420,7 @@ static u64 kvm_steal_clock(int cpu)
>  	return steal;
>  }
>  
> -static inline void __set_percpu_decrypted(void *ptr, unsigned long size)
> +static __always_inline void __set_percpu_decrypted(void *ptr, unsigned long size)

I'd rather drop the "inline" and explicitly mark this "__init".  There's value
in documenting and enforcing that memory is marked decrypted/shared only during
boot.

>  {
>  	early_set_memory_decrypted((unsigned long) ptr, size);
>  }

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aDCHl0RBMgNzGu6j%40google.com.
