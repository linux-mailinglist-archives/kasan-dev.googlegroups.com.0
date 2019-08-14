Return-Path: <kasan-dev+bncBDTN7QVI5AKBB2VH2HVAKGQE3MKQ5XQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 293658DD04
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2019 20:33:16 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id w5sf68796963pgs.5
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2019 11:33:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565807595; cv=pass;
        d=google.com; s=arc-20160816;
        b=fLLcNNK0DICo/iEwtTNwIlNfQdzwdnsdHlDmVjavdV8R3dgu1saydQ8Ce95s83qx4b
         lFqQYAX/0PkpVewgJ6Ni8jFv9O4ZzQ1rPtkmfzH40ANlwL09nDUepMkSDn49vD0ZLH/D
         WRxNhwAvW5UmUc3bRMJKPT50Ij+gAnH7Iw9qJ5jGVbV4/hrLjzDRbnPO1XOCPfDMgYf9
         HKecKsvXbjeXThrzWmQyL3CQolUON3Z7o3OLlEbsqBjWGra1VigqIHFgrHLvqgMKNIF1
         vkGbvnh61A/oXsl9xw5uimZ9ObpW+fJisEM/0dbAAMphoVpPwWu3dnS6lxyaRk3MD7RF
         ApNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=XmpnthaEvEiWQgzVdZ5K9y2VGwddsOuPMGwTfnh/Yl8=;
        b=bOTVC4myjYiUdtxpvai7ASrlcFEDmBrpaE3AoyvX4xmQQdYWMbLaR78RZeh/giE2n+
         FFbxWts02uIyvHeq0pI77ce0D2XI4vVLy29rO2FRnkom8TzLsAcjS39VfpeH9IoCrS2P
         4LwmYFWG5TffieGcIcra162mSjS1AzMKSzpCbSBCAd6acIWCImh7M85IJXHTxAy3jHzN
         bvTZYVy4Kzv855pnOJhvq/1KHS3z5R5sTSe8FQfGyZjgkJrn5Vjrokz5aIcJQOyXXp7x
         wTZqjvbREROEr4B3ikjWJmX/31uBbdrj2GgX5hehP9XElUSaCIS1CiXwOc9WNquUnzc5
         6aPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=OdbU6Wp7;
       spf=pass (google.com: domain of palmer@sifive.com designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=palmer@sifive.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XmpnthaEvEiWQgzVdZ5K9y2VGwddsOuPMGwTfnh/Yl8=;
        b=Big9Op+Jsx87Ms2c0BnyfMMi6Sr+xWD3Jeu74iHA7NQfuYkFGaxKIcrnPiyVglq8sR
         K4UIBfP57CSv7gqcydrdn+x2prAc+Qd62XJMhDfyF7XK2Q6c2rBDgKQqxY04vHzG5d6D
         umaPSUHP9pZIIUMxonk7TnPQuc0G23PmFMMLQRUMnF0WWi4espaCd8fsLyByIhNjzD1B
         Zt9ROcgqRB7bDuxPGK/cyE1+2JE9OSYmmX2VzEo0Fk6AR5oIjQduGeFCj2AJCS0HVLNB
         TTlGJzMbMfiYs+tRqvycw879B08MONyh8RBcnipcPaMRIk597GPdRWJXjonhnx4KDEFi
         Bi6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XmpnthaEvEiWQgzVdZ5K9y2VGwddsOuPMGwTfnh/Yl8=;
        b=M1lVgvRyAYbLGyaE20PKQ6Cm9iM/7wbzvRodidiT48HtQPzkN2lHtz73BkR4LeT3bS
         CMwCl++HClg0dUX3KuSYvGU5oXv76SSVFcCUFIQ+7fu+3J0iO5SvntKRIX672ljZ9PdV
         bMALL3zsTVdCm8h0nX5EHmnXuT3/x3mmfVCubOPpG0zXiIP+cTG00hx7H3NGrvtz05IZ
         JWb8G14RymHZ9nbrZ23D4oQ7SKk/YlAsMoSB8faV9Xk2bvCfol7ZptlVzzq+r649MT45
         Ag2++sfXHi521rUWYmyk8EC6ZYRWylUo6ZQbeKKcN5HZOHWFQQOPMw2F+AeA5Hjnf+/Y
         0kbg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVJN6IwgWiaPlFZc+i89gvS51QUgPjmLSDazoeEzd430vALvT1e
	u1etYbv9SVC4WoE6AZJS3GM=
X-Google-Smtp-Source: APXvYqxnMWRMV4Rd2SuhTFLErGnuBpbNMTfsu+lg6Zljashphwo+Mq4o+YLGO2f5GEi4GAMa66LkLw==
X-Received: by 2002:a62:174a:: with SMTP id 71mr1411516pfx.140.1565807594913;
        Wed, 14 Aug 2019 11:33:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:b518:: with SMTP id y24ls680630pfe.14.gmail; Wed, 14 Aug
 2019 11:33:14 -0700 (PDT)
X-Received: by 2002:aa7:83c7:: with SMTP id j7mr1380313pfn.59.1565807594593;
        Wed, 14 Aug 2019 11:33:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565807594; cv=none;
        d=google.com; s=arc-20160816;
        b=h+l6Sj0CjjZuAOmKxtmhBUjeMKtLMWh1K/JJMgtT880raPb6n3WoEMBkYjXRSgFmKw
         wlVXllEtNyDAMvSMKic54edEVBwJJkqgs2WYaiYEFzkScBJL+6skSg34jAdC6eNzFZhf
         71AM71ZD66gXXxrW1NxyRY5uhaDziBgGzTwoZqZ36DsZGuShWC91jFALNKz64r7U/S+k
         VyG0eVOeHCjB0cYtoDQlBbPIpcJsGoPsFpInUFwN5DfbJStPEdcx0yjLIIVbywZN5Vim
         JOGR0S5eO8q7HCl/O+EYpfyqrZ0QjFxZC3DSyKqdZJdw6eeI9+o9XVy2ojnIK2sa5a3/
         mTcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=FHbaVzjuuoyrLYUA3STjtrTGQSVNOY2GYHCncQDOa8Y=;
        b=Jw7g8byR/9voCRsCZZfph1xgOKV9EJWzqnWGI3P++EH2fjptDpeTR2XObYhhmKHlD5
         5nmtH9IPthqU7W6sW/R/T43iDvYJwBGCsVhEV/H+h5YpH6tdWMy8uSuN+Il7SFOA6qKb
         rFd7Nc109qkYaBBXbSzdhBshFNTxvtdkKjayGw/FzQX+i++tOU4egapE/bABQ7yU3zop
         GGYygRdMYDYy4F8qFWQOuAg+TwADeo/XXr0WRPTmvmujj1qJYp71t2SyCbWlE1gD+B7r
         sM67BqBijzF+1G18P8RiivTMYfze1s6owSpFgRIIBjalvs7Kn6bomo5Q1lN9nGFoLpEC
         Kwpg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=OdbU6Wp7;
       spf=pass (google.com: domain of palmer@sifive.com designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=palmer@sifive.com
Received: from mail-pl1-x641.google.com (mail-pl1-x641.google.com. [2607:f8b0:4864:20::641])
        by gmr-mx.google.com with ESMTPS id l72si38217pge.0.2019.08.14.11.33.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2019 11:33:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@sifive.com designates 2607:f8b0:4864:20::641 as permitted sender) client-ip=2607:f8b0:4864:20::641;
Received: by mail-pl1-x641.google.com with SMTP id 4so44049713pld.10
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2019 11:33:14 -0700 (PDT)
X-Received: by 2002:a17:902:8f93:: with SMTP id z19mr682659plo.97.1565807594175;
        Wed, 14 Aug 2019 11:33:14 -0700 (PDT)
Received: from localhost ([12.206.222.5])
        by smtp.gmail.com with ESMTPSA id r4sm580533pfl.127.2019.08.14.11.33.12
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Aug 2019 11:33:13 -0700 (PDT)
Date: Wed, 14 Aug 2019 11:33:13 -0700 (PDT)
Subject: Re: [PATCH 1/2] riscv: Add memmove string operation.
In-Reply-To: <alpine.DEB.2.21.9999.1908131921180.19217@viisi.sifive.com>
CC: Christoph Hellwig <hch@infradead.org>, nickhu@andestech.com,
  alankao@andestech.com, aou@eecs.berkeley.edu, green.hu@gmail.com, deanbo422@gmail.com,
  tglx@linutronix.de, linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
  aryabinin@virtuozzo.com, glider@google.com, dvyukov@google.com, Anup Patel <Anup.Patel@wdc.com>,
  Greg KH <gregkh@linuxfoundation.org>, alexios.zavras@intel.com, Atish Patra <Atish.Patra@wdc.com>,
  zong@andestech.com, kasan-dev@googlegroups.com
From: Palmer Dabbelt <palmer@sifive.com>
To: Paul Walmsley <paul.walmsley@sifive.com>
Message-ID: <mhng-22db5681-9fed-4bf6-83fe-180b3599c654@palmer-si-x1c4>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=OdbU6Wp7;       spf=pass
 (google.com: domain of palmer@sifive.com designates 2607:f8b0:4864:20::641 as
 permitted sender) smtp.mailfrom=palmer@sifive.com
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

On Tue, 13 Aug 2019 19:22:15 PDT (-0700), Paul Walmsley wrote:
> On Tue, 13 Aug 2019, Palmer Dabbelt wrote:
>
>> On Mon, 12 Aug 2019 08:04:46 PDT (-0700), Christoph Hellwig wrote:
>> > On Wed, Aug 07, 2019 at 03:19:14PM +0800, Nick Hu wrote:
>> > > There are some features which need this string operation for compilation,
>> > > like KASAN. So the purpose of this porting is for the features like KASAN
>> > > which cannot be compiled without it.
>> > >
>> > > KASAN's string operations would replace the original string operations and
>> > > call for the architecture defined string operations. Since we don't have
>> > > this in current kernel, this patch provides the implementation.
>> > >
>> > > This porting refers to the 'arch/nds32/lib/memmove.S'.
>> >
>> > This looks sensible to me, although my stringop asm is rather rusty,
>> > so just an ack and not a real review-by:
>> >
>> > Acked-by: Christoph Hellwig <hch@lst.de>
>>
>> FWIW, we just write this in C everywhere else and rely on the compiler to
>> unroll the loops.  I always prefer C to assembly when possible, so I'd prefer
>> if we just adopt the string code from newlib.  We have a RISC-V-specific
>> memcpy in there, but just use the generic memmove.
>>
>> Maybe the best bet here would be to adopt the newlib memcpy/memmove as generic
>> Linux functions?  They're both in C so they should be fine, and they both look
>> faster than what's in lib/string.c.  Then everyone would benefit and we don't
>> need this tricky RISC-V assembly.  Also, from the look of it the newlib code
>> is faster because the inner loop is unrolled.
>
> There's a generic memmove implementation in the kernel already:
>
> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/string.h#n362

That ends up at __builtin_memcpy(), which ends up looking for memcpy() for 
large copies, which is in lib/string.c.  The code in there is just byte at a 
time memcpy()/memmove(), which is way slower than the newlib stuff.

>
> Nick, could you tell us more about why the generic memmove() isn't
> suitable?
>
>
> - Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-22db5681-9fed-4bf6-83fe-180b3599c654%40palmer-si-x1c4.
