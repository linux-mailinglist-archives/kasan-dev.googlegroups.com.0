Return-Path: <kasan-dev+bncBCV4DBW44YLRB6UL2XXAKGQEKC6EN2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3177C103CAB
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 14:56:11 +0100 (CET)
Received: by mail-ot1-x33f.google.com with SMTP id 6sf13966225ota.6
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 05:56:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574258170; cv=pass;
        d=google.com; s=arc-20160816;
        b=LhHD6Eg7Odr4HVCJXauT+sPsvr/mWEccolFa4nIEhQyB8NLPYdpoCLwKoXDaWAbYwA
         jMJyZLEwl8I2qXpU3r6ukbBpHjS/ZJD4Yge4FutTqsvmmWpWXljLIZecJB3iqp1ECFyS
         aQDE/n8o2TWIzD74tnT8Rfpabcl6v4ZSrs2imKzbS9lMS//oTAK1S6IMISgmvVJWgSoy
         E29jkfIyY1GyNGZGlm2/RsjFXRdUagYGgKyYDLbbZ7clsk9MWxDb8V5kGiKIqXctPJJ0
         mauJsEM50jtr9NZM+fNMvoi3duq7ZuBjepwTyNljLhiU5A8K5Gh8onPFibcUM6v2p0VF
         x8sQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=2KXfsU1xVYlcBjHPFZpB8qZI3uZWCZwvWkcbWxfvCDE=;
        b=LEOYevtPjm08bK16iZwWfoSGsoI9tnIr0Jo8QU41GdkRj0xGYfDKPMGCzbB6gn8pHy
         1EjFvsp0dOyyy+snikXQV3YAwtORjC7qCwzcN94V7Fra6PDwz6PdoqaZFdNhuddcc/kU
         fHEORc+CwpJFC8z+tqpnUdWEf2ZbDNFp0CAHaa9BvcD6Jq9vSgEdRbi6llB7vPb2yRyj
         6or1RBsjV73Z/dqZRNoPOovDoGW+IcHr3vYy1PTxXdN4UE9qyGr9u5fmOw2HzeyYDVY1
         TFXJScdYPR5qiiX7mjHJoDIwwFU9sIttuQkcNMrOC9dq5Q5JPPl+InxWHcpET+Jmdp8D
         IBYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of ak@linux.intel.com designates 192.55.52.43 as permitted sender) smtp.mailfrom=ak@linux.intel.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2KXfsU1xVYlcBjHPFZpB8qZI3uZWCZwvWkcbWxfvCDE=;
        b=GSI/2oZ4tHceHYlqmYGl4K3v7xE4wsMpGJv1LydhSIVGYpMSchlDZfKIVxvhEXf+jN
         0TWkwQkpaGxY7UkmWLTKpbXdgP/bGfr9dOysMWznNUh52GcrUZECglydxr7HaWkT90yT
         tNLKO7RSdaOCUApMhTwQPJMYHqcHuPPbVqdfdSHQ7dwUx0wyldjDxaA5NX3xjLmE1JUh
         UnxVkxyrOSzKis/Zx45TBqR9HPdvR8dIaZgbG/qq8giGGh2l35VDV6kEbimZ+QHLP7Pf
         Q5X8pnr2Tu3tvEqJAYUyQkcZxLq+lsQWiRRAEfda1lFEyA+vqCUsijzab2PJfzaWerCD
         eLpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2KXfsU1xVYlcBjHPFZpB8qZI3uZWCZwvWkcbWxfvCDE=;
        b=QYGM+ou65P/Dzm5Tzc558YZcML5Sc5uAsE1ff6Xf6kIaj9Dp8lFh+eEsXm+8dMFaPu
         D61E6ytU2+iXiR8Cqncs67v88kByCRXU01lW875vrDhT3sRGKxayxuxnFbhf6AytSlFy
         ZhDQHamr6J9Y4qvoBnzdKHDTN1ED/04oFEu3l2t0WvQGQ8QFzyJKF4ohpi/kK9oJU7yN
         U4ce7uIRhkuYtKgBblzsr+QSYR6G1hFp3AheBzcmLY/3sedZu8mxHGOvQHnJqjK7ayO1
         2cK8KpUzwaXfL92MjnQySFU077ZqdIhSWIAegDBdNOI/RGRkMHC+Q4Rh1eJsh4ckUA63
         JdJA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWeNvfToNYzIWRFqBSaMHsDURd0iQNK5q+aqTPRszCOUwWTLLHg
	MqZMH1J0tZMZfhDrRdb2UTw=
X-Google-Smtp-Source: APXvYqyBi/D+B1lANX7HN3g9EnPOZa1zeyA5k6a9zrFrqowi/DYkyUJlKUI7qitaa9542wh1aV0gaA==
X-Received: by 2002:a9d:62d2:: with SMTP id z18mr2102485otk.108.1574258170054;
        Wed, 20 Nov 2019 05:56:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:4793:: with SMTP id u141ls346652oia.10.gmail; Wed, 20
 Nov 2019 05:56:09 -0800 (PST)
X-Received: by 2002:a54:481a:: with SMTP id j26mr3008259oij.20.1574258169730;
        Wed, 20 Nov 2019 05:56:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574258169; cv=none;
        d=google.com; s=arc-20160816;
        b=Fr+ACq6OodVRxM9RZ37liuO9b+h6L8u0z2ivQKlL8mKP+D0IcP+PwoaRbHSTcz+mkZ
         iLzgu6Gw9Z+EpUebjia3dqfu7VNnC61/clhcyRVZj0RRf9QzJ4kHm53T+pgGra/FkHpd
         ZJ7AaVyOoWtde7aHXkwhovPqB407zuAouOQuJTDwuKH3qzRphvLN4AOXbl4YoqhN52vh
         TEvyOaFEj3V7zHPw8IJccIpA/CCVhyAVhf3L5hr6GegFvMCVPShRoRyHOFibIzR8Iajl
         uNJzSAN2fRiHWWf/zXjXTbRpB11o2ctLJADqyidflrQMp3LijcKB3dt9yoXFsm4X3QhQ
         /PrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=BkPo4N+OXbR4oSS40xbBFhi4WIr8r7ec8ls0F/ll7a4=;
        b=CuDJmW5RFp9bkZ+YWzwc3FqArTzI10VtxHt6tlCsYpKnLvRj2IBcBss0y3lqjKzyhM
         3KjVb/WecUQzj2LQYvp/JWC5qhZstyXA/6296PH5K/vcOOu146d2/SUz5ymAVtLttGZV
         n+/p6dXLFqguFOpxzKaK2/bPUhlpouTvWxJV3ggjI2N5TpP18fzaKQUjPWY7p0J5EJgE
         uk5hXNAoSylPes8/RUqBNmy2qcBYnPQ9/PirM50QsPsjTX8YtMg9DYFniD2wccL0Zh1e
         8/WIx1o6Ll1deeG3Jk6qGW7xmiNFenTL7kRRFQToJVFoEGAKlGG6EQ43Dlko0tocezUF
         pTAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of ak@linux.intel.com designates 192.55.52.43 as permitted sender) smtp.mailfrom=ak@linux.intel.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga05.intel.com (mga05.intel.com. [192.55.52.43])
        by gmr-mx.google.com with ESMTPS id j190si1007757oib.0.2019.11.20.05.56.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 20 Nov 2019 05:56:09 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of ak@linux.intel.com designates 192.55.52.43 as permitted sender) client-ip=192.55.52.43;
X-Amp-Result: UNKNOWN
X-Amp-Original-Verdict: FILE UNKNOWN
X-Amp-File-Uploaded: False
Received: from fmsmga002.fm.intel.com ([10.253.24.26])
  by fmsmga105.fm.intel.com with ESMTP/TLS/DHE-RSA-AES256-GCM-SHA384; 20 Nov 2019 05:56:07 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.69,222,1571727600"; 
   d="scan'208";a="237738162"
Received: from tassilo.jf.intel.com (HELO tassilo.localdomain) ([10.7.201.21])
  by fmsmga002.fm.intel.com with ESMTP; 20 Nov 2019 05:56:07 -0800
Received: by tassilo.localdomain (Postfix, from userid 1000)
	id 1D7A330084E; Wed, 20 Nov 2019 05:56:07 -0800 (PST)
Date: Wed, 20 Nov 2019 05:56:07 -0800
From: Andi Kleen <ak@linux.intel.com>
To: Jann Horn <jannh@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>, "H. Peter Anvin" <hpa@zytor.com>,
	the arch/x86 maintainers <x86@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	kernel list <linux-kernel@vger.kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	Sean Christopherson <sean.j.christopherson@intel.com>
Subject: Re: [PATCH v2 2/3] x86/traps: Print non-canonical address on #GP
Message-ID: <20191120135607.GA84886@tassilo.jf.intel.com>
References: <20191115191728.87338-1-jannh@google.com>
 <20191115191728.87338-2-jannh@google.com>
 <87lfsbfa2q.fsf@linux.intel.com>
 <CAG48ez2QFz9zEQ65VTc0uGB=s3uwkegR=nrH6+yoW-j4ymtq7Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG48ez2QFz9zEQ65VTc0uGB=s3uwkegR=nrH6+yoW-j4ymtq7Q@mail.gmail.com>
User-Agent: Mutt/1.12.1 (2019-06-15)
X-Original-Sender: ak@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of ak@linux.intel.com designates
 192.55.52.43 as permitted sender) smtp.mailfrom=ak@linux.intel.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

> Is there a specific concern you have about the instruction decoder? As
> far as I can tell, all the paths of insn_get_addr_ref() only work if
> the instruction has a mod R/M byte according to the instruction
> tables, and then figures out the address based on that. While that
> means that there's a wide variety of cases in which we won't be able
> to figure out the address, I'm not aware of anything specific that is
> likely to lead to false positives.

First there will be a lot of cases you'll just print 0, even
though 0 is canonical if there is no operand.

Then it might be that the address is canonical, but triggers
#GP anyways (e.g. unaligned SSE)

Or it might be the wrong address if there is an operand,
there are many complex instructions that reference something
in memory, and usually do canonical checking there.

And some other odd cases. For example when the instruction length
exceeds 15 bytes. I know there is fuzzing for the instruction
decoder, but it might be worth double checking it handles
all of that correctly. I'm not sure how good the fuzzer's coverage
is.

At a minimum you should probably check if the address is
actually non canonical. Maybe that's simple enough and weeds out
most cases.

-Andi

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191120135607.GA84886%40tassilo.jf.intel.com.
