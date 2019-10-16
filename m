Return-Path: <kasan-dev+bncBD22BAF5REGBBXEDTXWQKGQER2SUJ7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id A4D45D96BA
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 18:14:21 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id e14sf38507367iot.16
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 09:14:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571242460; cv=pass;
        d=google.com; s=arc-20160816;
        b=JOVWWOyoPenTSIg/rgFfErOPlEy43ZgyRff70tqHIytPUajx4et2qiPeSMDZBdbBjE
         O2eaFhMT5jT2nEgezqmhqGLl/CLp4cDXBmf8qp7RB3qC7GxfwpstC4BV629DuaBMFJJd
         u/Ey6afHNqQGZcGDyT3sfXFQud9izxHJEUZFoFmYz4S0ygKFZbcyiEXI6VAoF2b8aeQw
         ydJn1oB/USgbnYYXvLqKrdhTLh8W0NmvFSNma/iVY5vmk60B1DY6uZy7RLXjF5Ssf8+F
         tdXlN7+wof118tmfy8hGK8vUouzkTYdhedxPZXyYEFnjWYrqkuEaEzZ18d+fBIX+AmFJ
         5mbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:openpgp:from
         :references:cc:to:subject:sender:dkim-signature;
        bh=FVBNn0U647bwsztAlklIATiU7RBEhpE9yVLQ4kGWpTc=;
        b=0hl9Kl7+4PphxUMnMWpn/TNrz5vKC0GvVFYWrcMVNR47bokL+XP+le0CsDDONsQsXj
         Izn8ccl7wBdfKAZ65ph/ZUnctmpdUIldhWAK6VCLOKrBd6H9q/fL2HPlUK2pSbATW29a
         NWoZCY1emHbhyha5MnZ6bKGqYE2GhjRQEjDV4FwVI8+DH+v1EzLTjqs5ALCSzVqm/fMH
         dv9LbWt6lsgfXMGLr9louZ9tC1AD6MBl31rv/+Mf0axsDh+URYikMWs4cywbD82M10ip
         cOIxO9BzhiaPM88oZ4AtY+o/aiDdVgsKaTFFasWMcMLBaZzYwu9epRA3zp7gKdQ7El5i
         YKdA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 134.134.136.126 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:openpgp:autocrypt:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FVBNn0U647bwsztAlklIATiU7RBEhpE9yVLQ4kGWpTc=;
        b=ESme7g9wCABEBjRiqRocbcr5DsfIINe2kTD0SlAcYpNbStcbzsHo3YN7/4TBvkS8lZ
         sOO6uee/1YRSsDRIPldoFnx5fwBejQakLIVdpcGWThmIUmePx5792BwmQx8p1G0etlPw
         gpRL63S7872ToXWIFRrzDwU/D1DygeREdN1RUYmOqaqHzmTE7sSo2wZdGyJ2iVTPq50i
         DzN8ayw3Tj5wIB0pa62IiWvQpyWdojZYeJkPpaUAbjc7Jd0bjRk1uZIFMVw8I0lO9v3G
         qa2WDKhTG8NR5tWS6bbXmL2thKf1OHJCXgzZ66a/dHeOkA4kwR+pnfnEoQ0UZ4GjPIPd
         AurQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:openpgp
         :autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FVBNn0U647bwsztAlklIATiU7RBEhpE9yVLQ4kGWpTc=;
        b=RzAUHiWZhZrucwMeweG1PhC4g+guBgnzKa+JGsGwiek9autuIltZThmP/OsCowP/zw
         Rm98zlfezBjovNXmL0wEvNmG5LcSfRPEwdJ7U3b0cZ9kOIHy1tuEDA351+eZ5LpPUk3n
         cXmSdMgWnIlv/yjaTxnr8XHys0lLNE8Z/WyH28L2yurpy+POmxAsxqeKSE44TXLF5Uue
         H3KJY+dmlIFgXBFjgQzUuYWGeRPjYvlw5HNdTsHDCTr+cBctaEoRNegAFli3l2We5oQU
         gankNuZUqG4nnj+/8NPh0EceTlg5sfzW9hqBBR6REKu8SGWEvm1RikXdpqv4n8oDz6MJ
         OU4w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVXgGaA+LQIISlMzoG393O9Qw6zLcAidpYAYOV5ffugDz/G0XoW
	5WlQNEAeHt1Y0CNjBOUwMKk=
X-Google-Smtp-Source: APXvYqyXPmoZPHa3dhNn2009CF6pHRk4i2siZQwVZge5mDy82uKYZKSMG7lJEU6zZVIuouiSJrQo7w==
X-Received: by 2002:a5d:974d:: with SMTP id c13mr1880014ioo.269.1571242460358;
        Wed, 16 Oct 2019 09:14:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:5edb:: with SMTP id f88ls2311182ilg.13.gmail; Wed, 16
 Oct 2019 09:14:20 -0700 (PDT)
X-Received: by 2002:a92:99c7:: with SMTP id t68mr3084026ilk.279.1571242460051;
        Wed, 16 Oct 2019 09:14:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571242460; cv=none;
        d=google.com; s=arc-20160816;
        b=nR61jxsOJzLcOwkOfexRMo6D4B2iCpNm0ZOzDAeuybLooXWJtIZSrK4BnxLn6DFLIQ
         tZduvg73d9BuZ1oZR7qmbY69b0DHqLUNx7F6atq7q0UJUMpuUMqspmOOUoQAWe0q5QME
         P/2EdTY4qd53kuNReU9MnDK4clcX7uJlgng409f3Sd8djd4evmNq3VLT1Z7Qi1PE/+Ov
         QnNde7GQ8qbLtZL6w0VFoYPnQ5m+90bOeLznO5+DE3TciX4hmamDzJuXok79kQeh5Oy7
         9jDAEKPEGQP56KaKIzZUQkRxbIDRcoo+xAtHOhGeKaDbblUT95okF8iHetntl00Moa1t
         CphQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:openpgp:from:references:cc:to
         :subject;
        bh=Q4JcRRWn4WcDItz4b9+oLlmwAhx3Z97P3ebILAC+1kE=;
        b=ypVlueL/mafCPRDoRNw2lMd/qrgNZyMFM2zIJPju31nDdOrZ0xC7ri0/WxLSJLpiDg
         JmLe7Vb3sGX5Gz27xT2hz6I8PvWqdAEPHvJygwfEVJbg12TBuSfoKFbEI0CIkW38Llf9
         CTD6xekfgNojzra0v7i02FB08ZPjcJukOsEOwHPTlo/SvIgZPYL2eTcDlJua3Gi7nGC5
         SDhlcUARwMSqtHEJG9nVa/ccMN5BO+N1MSyxk01n1r0XduAKcGNbMKZW3AhAdy0g30Jw
         8t9ok/pycUEpKrw89OfTpZWCtVAElz7XHfJqlSpiae+f113Oer5ou/2ga3s7Or3agMW6
         s1cQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 134.134.136.126 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga18.intel.com (mga18.intel.com. [134.134.136.126])
        by gmr-mx.google.com with ESMTPS id s5si615093iol.1.2019.10.16.09.14.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 16 Oct 2019 09:14:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 134.134.136.126 as permitted sender) client-ip=134.134.136.126;
X-Amp-Result: SKIPPED(no attachment in message)
X-Amp-File-Uploaded: False
Received: from orsmga006.jf.intel.com ([10.7.209.51])
  by orsmga106.jf.intel.com with ESMTP/TLS/DHE-RSA-AES256-GCM-SHA384; 16 Oct 2019 09:14:19 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.67,304,1566889200"; 
   d="scan'208";a="200106495"
Received: from unknown (HELO [10.7.201.139]) ([10.7.201.139])
  by orsmga006.jf.intel.com with ESMTP; 16 Oct 2019 09:14:18 -0700
Subject: Re: [PATCH 8/8] x86, kcsan: Enable KCSAN for x86
To: Marco Elver <elver@google.com>
Cc: akiyks@gmail.com, stern@rowland.harvard.edu, glider@google.com,
 parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org,
 ard.biesheuvel@linaro.org, arnd@arndb.de, boqun.feng@gmail.com,
 bp@alien8.de, dja@axtens.net, dlustig@nvidia.com,
 dave.hansen@linux.intel.com, dhowells@redhat.com, dvyukov@google.com,
 hpa@zytor.com, mingo@redhat.com, j.alglave@ucl.ac.uk,
 joel@joelfernandes.org, corbet@lwn.net, jpoimboe@redhat.com,
 luc.maranget@inria.fr, mark.rutland@arm.com, npiggin@gmail.com,
 paulmck@linux.ibm.com, peterz@infradead.org, tglx@linutronix.de,
 will@kernel.org, kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
 linux-doc@vger.kernel.org, linux-efi@vger.kernel.org,
 linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, x86@kernel.org
References: <20191016083959.186860-1-elver@google.com>
 <20191016083959.186860-9-elver@google.com>
From: Dave Hansen <dave.hansen@intel.com>
Openpgp: preference=signencrypt
Autocrypt: addr=dave.hansen@intel.com; keydata=
 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
Message-ID: <ce0d1658-c000-be20-c997-34ca488e4406@intel.com>
Date: Wed, 16 Oct 2019 09:14:18 -0700
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <20191016083959.186860-9-elver@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 134.134.136.126 as
 permitted sender) smtp.mailfrom=dave.hansen@intel.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On 10/16/19 1:39 AM, Marco Elver wrote:
> This patch enables KCSAN for x86, with updates to build rules to not use
> KCSAN for several incompatible compilation units.

First of all KCSAN looks really interesting!

For the x86 code, though, I'd really appreciate some specific notes on
why individual compilation units are incompatible.  There might be some
that were missed, and we have to figure out what we do for any future
work.  Knowing the logic used on these would be really helpful in the
future.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ce0d1658-c000-be20-c997-34ca488e4406%40intel.com.
