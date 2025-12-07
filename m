Return-Path: <kasan-dev+bncBC4LXIPCY4NRBJOC2TEQMGQEW7WYCYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C173CAB231
	for <lists+kasan-dev@lfdr.de>; Sun, 07 Dec 2025 07:39:42 +0100 (CET)
Received: by mail-qk1-x737.google.com with SMTP id af79cd13be357-8b1be0fdfe1sf122171585a.2
        for <lists+kasan-dev@lfdr.de>; Sat, 06 Dec 2025 22:39:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765089574; cv=pass;
        d=google.com; s=arc-20240605;
        b=Kzuqup9sEd98mR4LJijHzOb4JE8d+9DqRNh4LMXV1iRRlfmMtW450EFWIQrNlbAV5k
         FuWc/ilRuOah9XQLVk5RGmTxKqz3GxpmqVHo2dg1uB/gYjk69BLdC4uZtY7iJOaCa7sx
         fTxgDHxyKbwuA8rLzxpu7GyTyzJlldN7dXTKv0b7rYH1TXyad23Ahr6EBmotolIdNwmS
         HXASoORDWOW1dNK4C/WlfMotK4vVXp4gw6Zh89aiHiXzLFFrthahtQtrQ/oPJ3Oak9YW
         +VVaySm7kq+E69+Ht9PEMZDZIjQuJ93W0l332ZJJAogmPh2W4s2ovKl/CTFQcrfc23Mk
         0ftA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=lgwJGzqLZS7AganCLaZa86uqZxFKZThfRb/iaTXHdyw=;
        fh=IYlxDKrVhjvnWo2CGkqtGudLy4lLMRe44Un59f4OzgA=;
        b=lfXzQwv2hHrZGGx7ylG7kd2KIyzFzEnXmsr6KafG6sIQR88SPfGDdE249brrWyKuZ7
         UqPpbiatR9SS8YeUq3VwSxAzIpqrZEOdtaK1foTjhK40crw6e+IwTdoKyPcd7Sl4ReOO
         2uGm3wKbiiYPX71FJkpWQ36YtSxIvxLpl2UkrK96dFNhu3Mg9TBBIHHGw3mgmrVMO1np
         DhwWXkicT/0Hzr2LOmZ93GcGbExIX+UJb/+4aQTQO/7SncMPN3iE9cNP8ul56mPo8tcG
         0X4ac3v3CePyqxMJ+mF3xtrzyCReM8YfE7YmmJBlQva4RVvLFL9wBKZJBRyh+K2DswMv
         7U3A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=fnqrjoMj;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.8 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765089574; x=1765694374; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=lgwJGzqLZS7AganCLaZa86uqZxFKZThfRb/iaTXHdyw=;
        b=B4/IRHcbRFtDKbwNDLR5m1JXHXxyF4eOu5yPcpFYLj8k7X+5dXLCIxJcTsXbDzY9PJ
         j+2dytpeuqIkga5XOnmkxu8vWttuQCNXpMTuyKrePAReUziNbphQmAHGk6Jqe4Ew1N/H
         GAsJ66IkoU2XLxKPXdeYYpySlpW+mNM42JhBcfH6WYS+AzXcH3VmlfiZDkJiHkROtSTP
         fjdbHHWUBB77LQXi/VVsgchAin47avuz70mIiQ38EpyCNYP4MH4aJPIa43k7jjNYH9JT
         xR2p4bDoceR0g2YdAbkGbdCwAL+XE5NWz1rSAj6g5zLu/WlAW/p1x5fdZNCCXNUl6MY+
         PTqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765089574; x=1765694374;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=lgwJGzqLZS7AganCLaZa86uqZxFKZThfRb/iaTXHdyw=;
        b=jo/2N7cvzvEbOHmwiCz+62SXecTgHJdZM+JsxPBImYXVqQVzu0sNHY9CwheIY+P4qo
         uHAcRf0vTJotnc6qIMZ8KrBGhhDGL/RbiY5pdSvnUgh3/vIuLUI02GG49XSXWoeIWCvM
         wICxIjb+6DdWo8zL4pvPYRyV0Qjke/0tK7F0J337evGl1nBzoxsah/MkdKXS2GyQsp9N
         1f9mqHoxBNEfglKsQLUX9u6sjZZ5skSzThHQFqIy+eVC/nOGvtsSIIVrJvW0dS7wpDsi
         19pzKvYyPZcbd7vyTUR13/cHJDl/sAwOAGIqnItu1VOau4TG8ugEN20JknKmJ7ndg+fL
         lGQw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXeZkBXgSDUBBq1x/8umYZBW7muTz2K7q7NAPE7RPmIpeJpMogluGvWDa9rCCCEVXYyCsTwNg==@lfdr.de
X-Gm-Message-State: AOJu0Yx4BtdqG0qQA96i9oivLzLypMF5Ca6pNOa1PR7TBy9dDg9UeTW3
	YYiaZaPMlk8/WbymrzsinQhjoLdcoRgq6RawlKSoT7lwIHR3qOUc6qfX
X-Google-Smtp-Source: AGHT+IGY6SoCLuz3ZNpvMzWr8ecGeW7qZ1LPGk14AimHlwOl/OB8RURdMpDFQ75dIt1VgSPEX1GapQ==
X-Received: by 2002:a05:622a:1116:b0:4ed:6862:cdd0 with SMTP id d75a77b69052e-4f03fef4032mr53489071cf.10.1765089574092;
        Sat, 06 Dec 2025 22:39:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbcAOXZ10BuCdk5B60K+aw2HAD2xLz4uADtlgM+O5W1cQ=="
Received: by 2002:a05:622a:154:b0:4eb:7676:b2f with SMTP id
 d75a77b69052e-4f024c2bbafls67186191cf.2.-pod-prod-08-us; Sat, 06 Dec 2025
 22:39:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXRiqq8Nxeeb4bOX5OF+zgcivDx9rTRZZwdyitrKE3hVDYBoOa4lMGT8J9ba9+fi3cvM+YT7ZlgEwk=@googlegroups.com
X-Received: by 2002:a05:622a:ce:b0:4f0:237a:22fc with SMTP id d75a77b69052e-4f03ff1a482mr61515321cf.82.1765089573284;
        Sat, 06 Dec 2025 22:39:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765089573; cv=none;
        d=google.com; s=arc-20240605;
        b=VSL20Vra/LX9gHv+Jcv8S9shTnOuw+XYJ0jN7I930mydlTy5r6L7aTVCVSil+gQjsL
         W1i5nKS3Ey3mliIWhyFToC47kNxrDRpeFwCTS2Oh3YKGEhX6ZGgIORmHNmZlajL53GvN
         1MhBCznS8upsGauhyYPRGN5WZn3lZEvdi2lWmnv+EiBuWvS5pAuUWqZ9gsy+lJy7sXFM
         Rj3zCo0c4aT8ujAsjMQvKZtzRVyyIz4cbiPKTXdawW6XMkkbHWsDk2Zc9J3kFS2OJ1A3
         Xj0uQUfC8cz5t0VkFzxMimPVY2IYDhQq73OtLoVWAMem8bXQRWPe4S+Lkez3uOkSqk1V
         zRkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=qxfyjz7ZDFnStERhemLCGtg2Zk1HJsyxwmqJIWczdQE=;
        fh=kcPaEjtLbRgMXGuDHtmXdw1mznW1VyPnCvTxk3dMG3A=;
        b=k9zItDcUDdtijyGyQteiK/pEsrh80mGQp8xNs55h47+utGSr/agPLz6+KbRp1EP+c3
         cv/YJ1OY3LlRDI7jChQph7YAaaXsyDt+hm5Mt4mNY3fCvL7TXatEnDoCIvCnca+CwASH
         tp6RdKa2f2gIfcXjYRit005twTvvqlt46ENzWRbkHV+b5SqiB+Y0pKM33NfUpaOvkED7
         vLFf9rxyU/36Lo+CbuKBnrIvQdLoflBIKoT41JZBMZlOP/gIAKGwzoHFoFt3AxCJMDEb
         D4tb/q/iu32v0z/75ZYlWPCLF4nLSjaR/5MmNfqh4ZD/WM1mR5LEvSPQyUqMY4aGNJeC
         3+jw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=fnqrjoMj;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.8 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.8])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4f027c67619si3343711cf.4.2025.12.06.22.39.32
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sat, 06 Dec 2025 22:39:33 -0800 (PST)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.198.163.8 as permitted sender) client-ip=192.198.163.8;
X-CSE-ConnectionGUID: l2q6DdSxSj6upps1JPNhIA==
X-CSE-MsgGUID: DsZw2eXgTnK7Y+JcVvbQXQ==
X-IronPort-AV: E=McAfee;i="6800,10657,11634"; a="84665648"
X-IronPort-AV: E=Sophos;i="6.20,256,1758610800"; 
   d="scan'208";a="84665648"
Received: from fmviesa005.fm.intel.com ([10.60.135.145])
  by fmvoesa102.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 06 Dec 2025 22:39:31 -0800
X-CSE-ConnectionGUID: ZwBl5cWrTguiEMdSvIKppQ==
X-CSE-MsgGUID: hkd5k31qTfOs9Ov9tTdBXw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.20,256,1758610800"; 
   d="scan'208";a="200096334"
Received: from lkp-server01.sh.intel.com (HELO 4664bbef4914) ([10.239.97.150])
  by fmviesa005.fm.intel.com with ESMTP; 06 Dec 2025 22:39:25 -0800
Received: from kbuild by 4664bbef4914 with local (Exim 4.98.2)
	(envelope-from <lkp@intel.com>)
	id 1vS8QU-00000000J37-3Oir;
	Sun, 07 Dec 2025 06:39:22 +0000
Date: Sun, 7 Dec 2025 14:38:27 +0800
From: kernel test robot <lkp@intel.com>
To: Ethan Graham <ethan.w.s.graham@gmail.com>, glider@google.com
Cc: oe-kbuild-all@lists.linux.dev, andreyknvl@gmail.com, andy@kernel.org,
	andy.shevchenko@gmail.com, brauner@kernel.org,
	brendan.higgins@linux.dev, davem@davemloft.net, davidgow@google.com,
	dhowells@redhat.com, dvyukov@google.com, elver@google.com,
	herbert@gondor.apana.org.au, ignat@cloudflare.com, jack@suse.cz,
	jannh@google.com, johannes@sipsolutions.net,
	kasan-dev@googlegroups.com, kees@kernel.org,
	kunit-dev@googlegroups.com, linux-crypto@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, lukas@wunner.de,
	rmoar@google.com, shuah@kernel.org, sj@kernel.org,
	tarasmadan@google.com, Ethan Graham <ethangraham@google.com>
Subject: Re: [PATCH 05/10] tools: add kfuzztest-bridge utility
Message-ID: <202512071413.502tHWLT-lkp@intel.com>
References: <20251204141250.21114-6-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251204141250.21114-6-ethan.w.s.graham@gmail.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=fnqrjoMj;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.198.163.8 as permitted
 sender) smtp.mailfrom=lkp@intel.com;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=intel.com
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

Hi Ethan,

kernel test robot noticed the following build warnings:

[auto build test WARNING on akpm-mm/mm-nonmm-unstable]
[also build test WARNING on herbert-cryptodev-2.6/master herbert-crypto-2.6/master linus/master v6.18]
[cannot apply to next-20251205]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/Ethan-Graham/mm-kasan-implement-kasan_poison_range/20251204-222307
base:   https://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm.git mm-nonmm-unstable
patch link:    https://lore.kernel.org/r/20251204141250.21114-6-ethan.w.s.graham%40gmail.com
patch subject: [PATCH 05/10] tools: add kfuzztest-bridge utility
config: i386-allmodconfig (https://download.01.org/0day-ci/archive/20251207/202512071413.502tHWLT-lkp@intel.com/config)
compiler: gcc-14 (Debian 14.2.0-19) 14.2.0
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20251207/202512071413.502tHWLT-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202512071413.502tHWLT-lkp@intel.com/

All warnings (new ones prefixed by >>):

   Documentation/.renames.txt: warning: ignored by one of the .gitignore files
>> tools/testing/kfuzztest-bridge/kfuzztest-bridge: warning: ignored by one of the .gitignore files

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202512071413.502tHWLT-lkp%40intel.com.
