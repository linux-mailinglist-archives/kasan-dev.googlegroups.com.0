Return-Path: <kasan-dev+bncBDXY7I6V6AMRBL7DYOUQMGQEG2VSEAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id E9C747CF383
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Oct 2023 11:06:56 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-507cc15323asf1354816e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Oct 2023 02:06:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697706416; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZIOjDDYLsGA4/qC+rbp3OxAxvUUUlVTBvH2da7Im2ZElLdxUYSJycT5JkqbdgzT627
         /IuQKv+rrTcvTPJ7MdJRXRNZHpf2J4CZydEOhAJ3vUod2kOK+oSieFWjedZ5HiPoVL3w
         zjmevA1Qwgs0mypOz8y5ocfj21VG4nx/LJly8fr8qHldWQ2/IDJ5aLrqP402RzKEWnD1
         1s6+BdHgEPKW8PCwS13DlOt+P+Gzlr0dB9aVbfgKLnwMLB1vpNOAuJzuiAXilSA316nl
         FNefkAMi8IZ6Hq3SDPqlIAzon233HZuJH204AwCZDAVklbRF5WNGpRWTDl0w7J8X7UAQ
         xx6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=Qv52W1i+0aujwWhKUCTU9dSw+Y+3xQCcRzZVLpxtjJM=;
        fh=0lGrWxmvMNIlOXNBsi6VOpmYb74skFKWFziKrItfiiM=;
        b=QZjlderDKWUZ8WtPMJQ4ro0yrUrHxUJbebxkeTotEIP9OcrHHGEmAfU/NPmA/OEfPN
         0Y4MoQ7uaMN078AykBiw/SnLonMZH9pwDykwRfn6nW83YtMBz1eujf02qXjocrBHhhk8
         YvcayOe4+RKkXwktt05JTk/hdIwD1r7Bq+psefzLo5wvvF0e7ve633wQwLz6Qg81TIOH
         TtOkuZeE/n/iXUsrX/8f1xB73aTKlbdIa+HeNcMAAb03b4WXhf0oRdniBkMLyhrCZ2mG
         nyaPMFx5lbhgD6wZhUqpcVjPF5AkDO9v4xr6vmaQiRI5pDoD2DFUG1QDo+idtKLF03cZ
         B7AQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=p5iEF8h6;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697706416; x=1698311216; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Qv52W1i+0aujwWhKUCTU9dSw+Y+3xQCcRzZVLpxtjJM=;
        b=mC5yS0Y4sBikC43eEPCyo3n3RKXlRRVQvf/HF/L5vVVSWXsurSr2s6caaMFxuElNo8
         k0iApIQUbL/fPc5HOMwpu9wBfQMHeRvtfJU7x8S9GptlYB/aalpgVOsg2ZEOf9O51NRs
         iZP/+qLIOYr9rAxdakuwjGNEv/NAlRBKqiiM5nLeU6ZJpq2CdbGZlnZQrxiHbFgvduwU
         EMmdVdesQT9jdYUgTaLA+wYq/OzavqKPdVOZH5v95LcJ27erQnWXC5xIuDvVUXCrrtuG
         P0QawcROhWsRs+/8KV2UVd3xyekF62IrfsnTgAZgt2zXXu5LyVuLj/5PCGVBcWa6ZUWY
         JALA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697706416; x=1698311216;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Qv52W1i+0aujwWhKUCTU9dSw+Y+3xQCcRzZVLpxtjJM=;
        b=Qsqd7Z32c0nvK4eJI6j6ZOLAQWhbGsNRr5xuxb9gbKr6nHl9txorPzPDVvvqG+eAWX
         15SfCBEzZ4r5i1VFubrYfQpYLVyXbyNs+Hq3B60YyhAQyC5xfASgNLZJpz55S5JcbkrS
         xbAfhwM02o1OFlTzMnxooLYGvB2kgs/NYsBYYY5ou74d6amqULlY6ndvH6FDemwR4rTK
         1bYdstdK8eFzam2POE3WDOYtukLwqkT2JVq1ZZ2Zts2Li8gd8MGQVNVHc9SxP6tjShHP
         9QsFMCZOhpe7qh9c0LXXvzhvrgihWhrfzQRXOIOIWtesBRyfvsg0GfZcqI4jkhCYmf6k
         87uA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzN2rRSrAw4VaZ24jGj86HxC1QG6dArI8EiiXGlyjLsZFa4ycCY
	fqQOSCsVj4qv+8CGyiDLUSo=
X-Google-Smtp-Source: AGHT+IH6IAizyWIX1hr4OArOSvZZF9KOr2MuLFa9LMGa/79ixsbhHe4pz9vizUkjm/ZpwckNUPAw1Q==
X-Received: by 2002:ac2:5edb:0:b0:506:8e27:7ce9 with SMTP id d27-20020ac25edb000000b005068e277ce9mr1029316lfq.16.1697706415570;
        Thu, 19 Oct 2023 02:06:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:f07:b0:534:7b4a:8d91 with SMTP id
 i7-20020a0564020f0700b005347b4a8d91ls58745eda.2.-pod-prod-06-eu; Thu, 19 Oct
 2023 02:06:53 -0700 (PDT)
X-Received: by 2002:a17:907:9486:b0:9c6:8190:359f with SMTP id dm6-20020a170907948600b009c68190359fmr1250839ejc.33.1697706413702;
        Thu, 19 Oct 2023 02:06:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697706413; cv=none;
        d=google.com; s=arc-20160816;
        b=C18QBZN3E3NKExb1lWObUboP/haMAnQng5n6QyMa31sugp3yl2E/VhH0BzcSZLPBOV
         e0ykDvLyAqtHn/3YNPaCI7/YzaRQ9EsPutPxV1zpSxPZaDl1xCG0hGoyo1pHqnINXDI0
         6pX/+zQM0rzoLPDV960hwtI9iLNGk3EtwSGOrJKQ4bjgXQmqMZsCw45R4b9CZ6/g1fjU
         SfQ0BNc6Biz4a/ditRe0OwqSA2TyvyZl8r7dnHzkjKizWI+MuSeE/6ms0eDctgSMmbn2
         cxkqivIt+KMmo6SrA0yiQYXng8IQO7wQL71PIert6xjVMjHYHG+n27RhrN8dQoqHS3Iu
         pVow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=yTzH6q/KHuyR0ZINbw+hcjZ5+0x6X/p2cjmFJ06sw1g=;
        fh=0lGrWxmvMNIlOXNBsi6VOpmYb74skFKWFziKrItfiiM=;
        b=D1CDgCOIbAlJC7sm4Xb+aXCMElkz0oKedu/B5f/A2cM3OeoXGnaMECyTQcxYfNtie9
         Su+6Ac9A4n/E5gSCz0+oEgTbEZpXlR/Da8k4G5e/Z22ooU7MQGkLVhsYT5o5ffN5QNDP
         RO6b+rLcEuZ8GPCHgT+JCNISB5Mkp3pWr3scvxW48vyCs0MYzoqbn/ptrZDwVh2+Yjnv
         0hi5M5SXjciGbiDgsKaZKp5Xc3vyl54ONagAr6qiJai+FwnO1jdLLncOxJvUQewpXVOQ
         JSdDUWXzFTRIP2HFGeiIL4Esmit/boOsJtsBmGOOreP7+PB2CRsECCLIhzPUenIsrwjE
         k7jw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=p5iEF8h6;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id q24-20020a17090622d800b009adbab54deesi171103eja.2.2023.10.19.02.06.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 19 Oct 2023 02:06:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id ffacd0b85a97d-32dc918d454so1830859f8f.2
        for <kasan-dev@googlegroups.com>; Thu, 19 Oct 2023 02:06:53 -0700 (PDT)
X-Received: by 2002:adf:db4b:0:b0:32d:b06c:80b5 with SMTP id
 f11-20020adfdb4b000000b0032db06c80b5mr1127928wrj.2.1697706413344; Thu, 19 Oct
 2023 02:06:53 -0700 (PDT)
MIME-Version: 1.0
References: <20231002151031.110551-1-alexghiti@rivosinc.com>
 <20231002151031.110551-5-alexghiti@rivosinc.com> <20231012-envision-grooving-e6e0461099f1@spud>
 <20231012-exclusion-moaner-d26780f9eb00@spud> <20231013-19d487ddc6b6efd6d6f62f88@orel>
In-Reply-To: <20231013-19d487ddc6b6efd6d6f62f88@orel>
From: Alexandre Ghiti <alexghiti@rivosinc.com>
Date: Thu, 19 Oct 2023 11:06:42 +0200
Message-ID: <CAHVXubgZ12x5O4Uo404u8uL2qhrtdN5w-DQFvnBib3XhhtrK1Q@mail.gmail.com>
Subject: Re: [PATCH 4/5] riscv: Suffix all page table entry pointers with 'p'
To: Andrew Jones <ajones@ventanamicro.com>
Cc: Conor Dooley <conor@kernel.org>, Ryan Roberts <ryan.roberts@arm.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Anup Patel <anup@brainfault.org>, 
	Atish Patra <atishp@atishpatra.org>, Ard Biesheuvel <ardb@kernel.org>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, 
	kvm@vger.kernel.org, kvm-riscv@lists.infradead.org, linux-efi@vger.kernel.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=p5iEF8h6;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

Hi Conor, Marco, Andrew,

On Fri, Oct 13, 2023 at 11:58=E2=80=AFAM Andrew Jones <ajones@ventanamicro.=
com> wrote:
>
> On Thu, Oct 12, 2023 at 12:35:00PM +0100, Conor Dooley wrote:
> > On Thu, Oct 12, 2023 at 12:33:15PM +0100, Conor Dooley wrote:
> > > Hey Alex,
> > >
> > > On Mon, Oct 02, 2023 at 05:10:30PM +0200, Alexandre Ghiti wrote:
> > > > That makes it more clear what the underlying type is, no functional
> > > > changes intended.
> > >
> > > Scanning through stuff on patchwork, this really doesn't seem worth t=
he
> > > churn. I thought this sort of Hungarian notation-esque stuff was a
> > > relic of a time before I could read & our docs even go as far as to
> >
> > s/go/went/, I see the language got changed in more recent releases of
> > the kernel!
>
> The documentation seems to still be against it, but, despite that and
> the two very valid points raised by Marco (backporting and git-blame),
> I think ptep is special and I'm mostly in favor of this change. We may
> not need to s/r every instance, but certainly functions which need to
> refer to both the pte and the ptep representations of entries becomes
> more clear when using the 'p' convention (and then it's nice to have
> ptep used everywhere else too for consistency...)
>
> Anyway, just my 2 cents.

I started changing that in one function and another one, and another
one...etc up to every instance. I still think that it makes things
clearer, but that's subjective, you raised valid points and I'd really
like to see this land in 6.7 so I'll revert this patch and send a v2.

Thanks for your feedbacks,

Alex

>
> Thanks,
> drew

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAHVXubgZ12x5O4Uo404u8uL2qhrtdN5w-DQFvnBib3XhhtrK1Q%40mail.gmail.=
com.
