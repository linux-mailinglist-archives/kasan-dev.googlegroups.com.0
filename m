Return-Path: <kasan-dev+bncBDQ27FVWWUFRB2GPSXWQKGQENYLSZLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id 61ED2D6F9A
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2019 08:32:09 +0200 (CEST)
Received: by mail-vk1-xa40.google.com with SMTP id b11sf4885899vkn.1
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 23:32:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571121128; cv=pass;
        d=google.com; s=arc-20160816;
        b=cys/LLVwEg8F9YmZoalzsjdZJHmki3PF8M9wM1yJKXUj8rmdIx0cJNy1OcAWbTTC7G
         epSWvtfYrzOB6dEvVJxr3h/8Ad1sTfEtOLGWxpxsC2FX2VsA/RMk2siSMJtBH4eH8Qh+
         /l2yx+5k1D+R4wTIfjeauMoWOVGNltWWA8Qk/sD/tNaj8cReNJWitDz8m8JaeG0ktP4h
         yB/h3mivx1ML5UUYQjOSmCsojWnJ0EwuEDHlS1e+5OaqIhecCjKcTgGMfiP0+z0Yumuv
         f3ngNC4uREc9k6VtLPChtw3zqwy+y+EFZ3K2UHpXnf7/y553eodyOr6MPq8ms/jtQKiT
         mVHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=pkOemkiMggcaLIRuJ+GwAcz/XdcTj5R8TqX3Ibal8XA=;
        b=tuL1JcS4EF6AfclZcAV496xJYCZORc4F+QJiQGLo2CpY6/SxH0qR59tYI+R+ZIBL58
         XnCQ2szqfxOjY7MQC2CdrWJuqQMWjwqVEkm2AalYv3KJFvkdihH4H4dKuRD14x2WjZzG
         AaATolIqAfxNjrrmLomkmg0CPlFACh9nlSUQyKi634+8+YugNpWTdyWWTChrD55GMxud
         Ez9oqgHrPt3jgWhNk6+oty2SGMQpgscqdRInMPnKHArkARlxu6IEr1uRL8X1JWWXL+lX
         0c1UsVmE3zRdqPPLixrvSeZQFxP0f9E+2F/cjDVx+QJVTbMAMKhBd7+pM7E8a5IcLtMq
         M/UA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=AAAw2I6J;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pkOemkiMggcaLIRuJ+GwAcz/XdcTj5R8TqX3Ibal8XA=;
        b=CDPEAu2gvfL8rvIhUET/oOSZ9QsxNHh0ecuYfLJUhyPMSvaFbeDykmgH9ujRmhT+uj
         K/NjjyKNn/3ennwtkYOTwyYmCSrtrt88fEDwoTKAI2aLvzUfystHImGcr6VPBryM9sCR
         MjRBbh75B8vn4zjmJhupcEXnFhpB917AEmASB/xXnFrIqphGBjD46zAlIKqwEmNHxzKk
         w0f0XWkB30Q1Dlr6+bNM+crtgD/5qXLggQ74ZsiIKTt8UV2PEDKjBMJPB4t1BedWk/Wb
         vIN3mUA4jyegRLgYBE1s6wcnxEqg4XJUoxCmb+4TQnEfigBEJw+pP8DZwRKsHgj0EXCs
         VLJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pkOemkiMggcaLIRuJ+GwAcz/XdcTj5R8TqX3Ibal8XA=;
        b=GDdB1H3nwSa+uzBqNT908n2eZCAsFqoDKQPz7JU23DoCfhKepfhf6hYvHaMOqBa3+b
         5p7rT037N8vg26OEX2DCbitzBtkFkwtmLvMkSx83G2I55NfYd4T5XeK3faWfat0e6Qcm
         u6Dfkr56S0ma/QP8E7TI1AQLAaQnCHkHyMyC1OAc9Y4RxYQtj8HSry4WAGU9cUZ+yiqA
         JvqwldtwCxTatWYqznGa7sbUkEVUisHF/MkB2zgsKvfnks2/hrx8myeL5ZqbAl4r+V7y
         gnTBk+ImzJ/OlR8OqcvVaN1xrPX1pYyEylZN/+duZ3ZT2b+fm+cgX85mATU7Q0fT6vWc
         jaKg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWKl0iC8ssSVIayu+0y77+B64pc/zFI6dgx7qy5EvNT/Rn6QcJB
	AXyyXoD5WmNMBpZhyUqpEzA=
X-Google-Smtp-Source: APXvYqw5JyNt7iiYl26d7AFPsazIfJMTFRc8cnfAuFu+3GX1EzqK8jBiU3kGyCpX94TKfscYyGlDGQ==
X-Received: by 2002:ac5:c285:: with SMTP id h5mr11643965vkk.74.1571121128384;
        Mon, 14 Oct 2019 23:32:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f491:: with SMTP id o17ls1643175vsn.16.gmail; Mon, 14
 Oct 2019 23:32:08 -0700 (PDT)
X-Received: by 2002:a67:fb44:: with SMTP id e4mr19101031vsr.112.1571121128013;
        Mon, 14 Oct 2019 23:32:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571121128; cv=none;
        d=google.com; s=arc-20160816;
        b=K4wURbbyNU5ieM3tir/65MZTcCGgZhP5Lt9pFq3Htv56JEBbfhzVVAU0LU0kCnPuQN
         4ABz4uprrdD/zTOamTauOFWbDzbUiQyACr73Y7VjGdl9qYE8bgiWhS76rn6yrRJws7uM
         MjTobXGWUovBqQpvCV9Q9++oKnUU9AXUeYfOXcgeWAxs0GVXj5GrZECG57ubz5Y81KYa
         mAji+3RuTT0T8DmBx6BUNQDcPVKWj4rYLFv5uhN2T8IjGRqXV3QCG3iJsQguJBejCI15
         aBelM7D/k6n/l8bbU5SDgmPhp1dT9dFd9f2XkFtDXcaabSHAvo70Gkc9Sf6Ygb1gtl6/
         QqqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=ocFENo40eBkOamSyXJJZMLvSNduSNIAZPjJ2SmsMR/E=;
        b=uwUHrb7Pt21eYw8oKVYXZE+ZdVxcwlA0z2ZIwt61NXejZkBEZVF7tfKG+EBjCKEiaj
         TmEHuiBi/wlUpoGlmhF5SXB5wX+SOwX4OoEW3cY1s537Pw7nfSH5UlVQe5TbpRV4XgyK
         6bVEFaSyzHAY+Z7kA2/ewIbXgkRIcU9gz/+/LNmNHLuCqp967KIkHT56ORzR0rL9ApAg
         HT0OTqQImGBD5y6W3o2R1DGBJMO8U9Wnjy2zbOitM6g7aYJhUWnccqxInYnvttvlVAlf
         y8Xrb4vGJlw9Pq0e3WHgZkUU081eY95+jUTa9Y0019JsMUCdY1hIIqGt2mm0D2iFrG7X
         P2hQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=AAAw2I6J;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id u65si446019vsb.0.2019.10.14.23.32.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2019 23:32:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id b128so11816387pfa.1
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2019 23:32:07 -0700 (PDT)
X-Received: by 2002:a63:7405:: with SMTP id p5mr37573902pgc.264.1571121127089;
        Mon, 14 Oct 2019 23:32:07 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id i1sm24230357pfg.2.2019.10.14.23.32.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Oct 2019 23:32:06 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Mark Rutland <mark.rutland@arm.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, x86@kernel.org, glider@google.com, luto@kernel.org, linux-kernel@vger.kernel.org, dvyukov@google.com, christophe.leroy@c-s.fr, linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com
Subject: Re: [PATCH v8 1/5] kasan: support backing vmalloc space with real shadow memory
In-Reply-To: <20191014152717.GA20438@lakrids.cambridge.arm.com>
References: <20191001065834.8880-1-dja@axtens.net> <20191001065834.8880-2-dja@axtens.net> <352cb4fa-2e57-7e3b-23af-898e113bbe22@virtuozzo.com> <87ftjvtoo7.fsf@dja-thinkpad.axtens.net> <20191014152717.GA20438@lakrids.cambridge.arm.com>
Date: Tue, 15 Oct 2019 17:32:03 +1100
Message-ID: <875zkqtt7g.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=AAAw2I6J;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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


> There is a potential problem here, as Will Deacon wrote up at:
>
>   https://lore.kernel.org/linux-arm-kernel/20190827131818.14724-1-will@kernel.org/
>
> ... in the section starting:
>
> | *** Other architecture maintainers -- start here! ***
>
> ... whereby the CPU can spuriously fault on an access after observing a
> valid PTE.
>
> For arm64 we handle the spurious fault, and it looks like x86 would need
> something like its vmalloc_fault() applying to the shadow region to
> cater for this.

I'm not really up on x86 - my first thought would be that their stronger
memory ordering might be sufficient but I really don't know. Reading the
thread I see arm and powerpc discussions but nothing from anyone else,
so I'm none the wiser there...

Andy, do you have any thoughts?

Regards,
Daniel

>
> Thanks,
> Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/875zkqtt7g.fsf%40dja-thinkpad.axtens.net.
