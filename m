Return-Path: <kasan-dev+bncBD22BAF5REGBBTFA37FQMGQE252LFUI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id CF3WHk/Qd2mxlQEAu9opvQ
	(envelope-from <kasan-dev+bncBD22BAF5REGBBTFA37FQMGQE252LFUI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 21:36:31 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 15F978D1F4
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 21:36:31 +0100 (CET)
Received: by mail-pg1-x53f.google.com with SMTP id 41be03b00d2f7-c5539b9adbcsf1068372a12.3
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 12:36:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769459789; cv=pass;
        d=google.com; s=arc-20240605;
        b=Av2YTW2wQa6lnIVYjPRcQOOSbKXS5IoI5Fvqt9O9EMLIuagX5DMtuXEhy1ehfrFCnb
         r2GitkL4AQ+PxHrQ4O3zmx58TSaMajvHfFSQJ/WiEB4PiGmohqTZx7RPWjbXs/OD0eJD
         0UwVIbtZXOVmQbRihVpAuDa5f8lCpwr6YtpjKFOOAuTkC/zhhJg22TecT6/E3oySK7+X
         RFJr6n0MM19o/gMzPXrCYT+QY4O3ftmVZ4oM0kgRxL6SJqk5lS/+lLnUJ0Lj8yM/csp5
         giZwCTGlRivX14r/YjTAY5+6deZ3kN++MNLMy/gqaN5oxua+eL+yzwkMRW/9EaTU7Pc5
         cTaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=cfwQMcLnaJ1dfZXtBsyAFkzqoLXROaVA65WoyrvwLrY=;
        fh=wJU2k9Fkm1D80qFQ2fzPqVd18PdBVUOcF81p63ff74s=;
        b=F023TON48D+KjlewHTd7WHCuGcCICS5+I8rauPYh7OY9BnuVH4h4FQHKrEtto2uZ/V
         qDEa6/EFAEF8ftxmREeYqsrYMOo6lbkveVgkBZNhZlqLO6jh6jnHc2g6CxvN6zyjrBeR
         xZX4joSXd/XdN5ogLEX534vitJXzGITXrhfuRfhrAF6ME9kmISdakCoaDOWmNhTJNmOf
         bYY4FU2ReKfSHk2V5n9YxYqrbZj5IsDiyyPsA/QPSGk2Kgrlcq5bopYdM5m0fpsbSX+R
         DeHhReXgILXYlRnJJJoBzHonrBPO9HCw582zymCIbQc/lIGAbKnX2pdZ9BtlOoSuZwkn
         Xniw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="VN/SMF2E";
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769459789; x=1770064589; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=cfwQMcLnaJ1dfZXtBsyAFkzqoLXROaVA65WoyrvwLrY=;
        b=XaSAmT4ntQkartP2GUURb2U7Buvir8N1bLcPd17b6BYbv1ooz/YlDw1jfdCY+GjH8Y
         rnvbHus6IeQjABe7VvkbhgodKBCvWMxI3M4a7qT0K6sqCGASNNaZmwe69QYJwgVZPKZm
         JNoIxw0r9f6V+84W0JVKbBfCqJOFbGn9EcfTsvApm4a34i83vAyhbR5bmhSs4OL47s+9
         8vRqxOC2zsK0fo4eUNeADOOqmWTjVMYg9N2xBDD5nYeDHtiFjKFJYk5w1JBupo0MwJlJ
         zDdkYmzrko5AYskuoJQTcjwK7f26DkSYbA+Yyf6y05cWvoUagaZjfWgunPbsupQ0+rhT
         hEwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769459789; x=1770064589;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=cfwQMcLnaJ1dfZXtBsyAFkzqoLXROaVA65WoyrvwLrY=;
        b=c8fn7eMCzihEk7x7HgpA5luGyN+OX24wOT2SOmWsiBP+Pbg/bR0Og2o6w7Giq3wzwf
         rdvnU4Pl4oubySH5/AyJPjyduGNE1asaku7WTHW2iKS2YynQwesV6GimCR/9pnERUkfi
         75STxWM62+E3zYDWUFWLNq5dYQXz0B3qkzvQJYqRRC7w7UJZ56E9PDNpE86Yut1MJWXU
         GTmZZDINH8z6I8s1gQ2EW6f4lHqFrOn2vRLGORQ1Ajc66/jmD9+917EM7EpeKK/G5Wt0
         zTEmxXjWs+vWD23ux2nTu/RZCYH2MklueRtp8jukgOIGllcUrGUKge57GaeGZfijcakf
         TSHw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXLMyrQt1pkH/QOiqX2FnxAzZcvRC5YiHXOppSt9u59LFk5Y/4eDIqc/T8yIILLebbSWpBphg==@lfdr.de
X-Gm-Message-State: AOJu0YzW86spd1f1RzdX1l9rybb6KN2wgVGnPectqZq1XSL8Z+QfKSX9
	ZJpeTaWHYY4dQ6Czr0qNfljqRKaexZqkZ9FAl4ntsYXI60VRvaY2+sRT
X-Received: by 2002:a05:6a00:4f91:b0:81e:f623:ba0c with SMTP id d2e1a72fcca58-8234129f6e8mr4891403b3a.44.1769459789406;
        Mon, 26 Jan 2026 12:36:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FyMt1fDC9/62qP/rneeaWf+2k5J1foKB9y+dVXw0dhZQ=="
Received: by 2002:a05:6a00:f:b0:81d:bac0:c3f0 with SMTP id d2e1a72fcca58-821ef2cff48ls3867409b3a.2.-pod-prod-08-us;
 Mon, 26 Jan 2026 12:36:28 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUy2GJDnmrNUDaDtyRMh2F7FNkmunz6CkR6QGoizhZoEA51mkaP0hhBgcvZ3MICl18OQD82viBMy58=@googlegroups.com
X-Received: by 2002:a05:6a00:1591:b0:81f:4ce8:d642 with SMTP id d2e1a72fcca58-823412d2fa2mr5041380b3a.64.1769459787852;
        Mon, 26 Jan 2026 12:36:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769459787; cv=none;
        d=google.com; s=arc-20240605;
        b=R+aGPjsv3Ui1Q8TFeWwlH2SbcuHRlEwHMrD+sXAlUfbYA8TW7ORcnJHt4OTVlT0tKE
         ea0Kgwb78zk/wjU2S7c26tfsljT3ihy1WsRa83HT2Ofaz7SGnjhTQzdzvELZcKHOL1mv
         QjvP9QJQEs4lvXbfg2p2eJcXhFyoJANzUQJsp/nVGwSDivc+5BshkuGiPAdPl1LYAFXo
         qWmQRtXRqI+g/BxxgjTUzrlKbx6OLI1E6ZCru8jrCgQxkY0/PHe9hTlX0QSoaixtQWHy
         qelXJqsTW7M6KRlmqqavwTemVcpIX1IMDjYLBhLnzSIAN2iNFytNy8rhgfCHXWZv3ibf
         bsNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:content-language
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=+ynX/Cn7qIf7TOE0cAEvkVf4W/kMEyuHm8rD2lSuK48=;
        fh=31HpmkfUQkSXhR+SJuBlHGb4bLovdsC3p4RBRj+aN1k=;
        b=U4ov6Wnh5TGKNLHEI+KJajBuykmcHXQgnmDaW50yR/egPTUHtPjWjneP/TEYL19Ts+
         Jbp5SUxrwAwT4jHr81MtiK026zrPWQh8WpF8ot3gVBkC2LoFvpC+jHbfCJ8nAf043ZnM
         SksA5/9gPfwl6CDuqWNlWn50eG/qXJz1kgi3cvVoXJWYBH7kjKqhd0OFf2m/IbJFyEBJ
         bnnqi4XhlI8CNI1VWNHAyyUpJa9ybVmZc81eMtjIGZxOWGJw6d1vHbBpKvCOBZOTwyJ3
         WlxELlTfuyJPtYs7ViAb5P4/crWGAwIjau8Ce+PKaCTRxZ5v7jWEYxNxyuksPKxSURER
         HZAQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="VN/SMF2E";
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.11])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-8231875d512si354413b3a.9.2026.01.26.12.36.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 26 Jan 2026 12:36:27 -0800 (PST)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.11 as permitted sender) client-ip=192.198.163.11;
X-CSE-ConnectionGUID: nj/HNes2SAaJnwEJyJ7LtA==
X-CSE-MsgGUID: +1gHrfRASt6uzhn8ixaqFg==
X-IronPort-AV: E=McAfee;i="6800,10657,11683"; a="81276249"
X-IronPort-AV: E=Sophos;i="6.21,255,1763452800"; 
   d="scan'208";a="81276249"
Received: from orviesa003.jf.intel.com ([10.64.159.143])
  by fmvoesa105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 26 Jan 2026 12:36:26 -0800
X-CSE-ConnectionGUID: zj2TwRUrRjyT/gd+MQ9gZA==
X-CSE-MsgGUID: 9e8HxKV5SiaM/QSmlx0Rgw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.21,255,1763452800"; 
   d="scan'208";a="211882061"
Received: from rchatre-mobl4.amr.corp.intel.com (HELO [10.125.109.65]) ([10.125.109.65])
  by ORVIESA003-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 26 Jan 2026 12:36:25 -0800
Message-ID: <dc5326fa-955b-44fe-abbd-ab1bf0675529@intel.com>
Date: Mon, 26 Jan 2026 12:36:25 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [REGRESSION] x86_32 boot hang in 6.19-rc7 caused by b505f1944535
 ("x86/kfence: avoid writing L1TF-vulnerable PTEs")
To: Andrew Morton <akpm@linux-foundation.org>,
 Ryusuke Konishi <konishi.ryusuke@gmail.com>
Cc: Andrew Cooper <andrew.cooper3@citrix.com>, Marco Elver
 <elver@google.com>, LKML <linux-kernel@vger.kernel.org>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
 Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>,
 X86 ML <x86@kernel.org>, "H. Peter Anvin" <hpa@zytor.com>,
 Jann Horn <jannh@google.com>, kasan-dev@googlegroups.com,
 stable <stable@vger.kernel.org>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
References: <20260106180426.710013-1-andrew.cooper3@citrix.com>
 <20260107151700.c7b9051929548391e92cfb3e@linux-foundation.org>
 <CAKFNMokwjw68ubYQM9WkzOuH51wLznHpEOMSqtMoV1Rn9JV_gw@mail.gmail.com>
 <20260126122440.78e7ffebd5257e5ce00fa35a@linux-foundation.org>
From: Dave Hansen <dave.hansen@intel.com>
Content-Language: en-US
Autocrypt: addr=dave.hansen@intel.com; keydata=
 xsFNBE6HMP0BEADIMA3XYkQfF3dwHlj58Yjsc4E5y5G67cfbt8dvaUq2fx1lR0K9h1bOI6fC
 oAiUXvGAOxPDsB/P6UEOISPpLl5IuYsSwAeZGkdQ5g6m1xq7AlDJQZddhr/1DC/nMVa/2BoY
 2UnKuZuSBu7lgOE193+7Uks3416N2hTkyKUSNkduyoZ9F5twiBhxPJwPtn/wnch6n5RsoXsb
 ygOEDxLEsSk/7eyFycjE+btUtAWZtx+HseyaGfqkZK0Z9bT1lsaHecmB203xShwCPT49Blxz
 VOab8668QpaEOdLGhtvrVYVK7x4skyT3nGWcgDCl5/Vp3TWA4K+IofwvXzX2ON/Mj7aQwf5W
 iC+3nWC7q0uxKwwsddJ0Nu+dpA/UORQWa1NiAftEoSpk5+nUUi0WE+5DRm0H+TXKBWMGNCFn
 c6+EKg5zQaa8KqymHcOrSXNPmzJuXvDQ8uj2J8XuzCZfK4uy1+YdIr0yyEMI7mdh4KX50LO1
 pmowEqDh7dLShTOif/7UtQYrzYq9cPnjU2ZW4qd5Qz2joSGTG9eCXLz5PRe5SqHxv6ljk8mb
 ApNuY7bOXO/A7T2j5RwXIlcmssqIjBcxsRRoIbpCwWWGjkYjzYCjgsNFL6rt4OL11OUF37wL
 QcTl7fbCGv53KfKPdYD5hcbguLKi/aCccJK18ZwNjFhqr4MliQARAQABzUVEYXZpZCBDaHJp
 c3RvcGhlciBIYW5zZW4gKEludGVsIFdvcmsgQWRkcmVzcykgPGRhdmUuaGFuc2VuQGludGVs
 LmNvbT7CwXgEEwECACIFAlQ+9J0CGwMGCwkIBwMCBhUIAgkKCwQWAgMBAh4BAheAAAoJEGg1
 lTBwyZKwLZUP/0dnbhDc229u2u6WtK1s1cSd9WsflGXGagkR6liJ4um3XCfYWDHvIdkHYC1t
 MNcVHFBwmQkawxsYvgO8kXT3SaFZe4ISfB4K4CL2qp4JO+nJdlFUbZI7cz/Td9z8nHjMcWYF
 IQuTsWOLs/LBMTs+ANumibtw6UkiGVD3dfHJAOPNApjVr+M0P/lVmTeP8w0uVcd2syiaU5jB
 aht9CYATn+ytFGWZnBEEQFnqcibIaOrmoBLu2b3fKJEd8Jp7NHDSIdrvrMjYynmc6sZKUqH2
 I1qOevaa8jUg7wlLJAWGfIqnu85kkqrVOkbNbk4TPub7VOqA6qG5GCNEIv6ZY7HLYd/vAkVY
 E8Plzq/NwLAuOWxvGrOl7OPuwVeR4hBDfcrNb990MFPpjGgACzAZyjdmYoMu8j3/MAEW4P0z
 F5+EYJAOZ+z212y1pchNNauehORXgjrNKsZwxwKpPY9qb84E3O9KYpwfATsqOoQ6tTgr+1BR
 CCwP712H+E9U5HJ0iibN/CDZFVPL1bRerHziuwuQuvE0qWg0+0SChFe9oq0KAwEkVs6ZDMB2
 P16MieEEQ6StQRlvy2YBv80L1TMl3T90Bo1UUn6ARXEpcbFE0/aORH/jEXcRteb+vuik5UGY
 5TsyLYdPur3TXm7XDBdmmyQVJjnJKYK9AQxj95KlXLVO38lczsFNBFRjzmoBEACyAxbvUEhd
 GDGNg0JhDdezyTdN8C9BFsdxyTLnSH31NRiyp1QtuxvcqGZjb2trDVuCbIzRrgMZLVgo3upr
 MIOx1CXEgmn23Zhh0EpdVHM8IKx9Z7V0r+rrpRWFE8/wQZngKYVi49PGoZj50ZEifEJ5qn/H
 Nsp2+Y+bTUjDdgWMATg9DiFMyv8fvoqgNsNyrrZTnSgoLzdxr89FGHZCoSoAK8gfgFHuO54B
 lI8QOfPDG9WDPJ66HCodjTlBEr/Cwq6GruxS5i2Y33YVqxvFvDa1tUtl+iJ2SWKS9kCai2DR
 3BwVONJEYSDQaven/EHMlY1q8Vln3lGPsS11vSUK3QcNJjmrgYxH5KsVsf6PNRj9mp8Z1kIG
 qjRx08+nnyStWC0gZH6NrYyS9rpqH3j+hA2WcI7De51L4Rv9pFwzp161mvtc6eC/GxaiUGuH
 BNAVP0PY0fqvIC68p3rLIAW3f97uv4ce2RSQ7LbsPsimOeCo/5vgS6YQsj83E+AipPr09Caj
 0hloj+hFoqiticNpmsxdWKoOsV0PftcQvBCCYuhKbZV9s5hjt9qn8CE86A5g5KqDf83Fxqm/
 vXKgHNFHE5zgXGZnrmaf6resQzbvJHO0Fb0CcIohzrpPaL3YepcLDoCCgElGMGQjdCcSQ+Ci
 FCRl0Bvyj1YZUql+ZkptgGjikQARAQABwsFfBBgBAgAJBQJUY85qAhsMAAoJEGg1lTBwyZKw
 l4IQAIKHs/9po4spZDFyfDjunimEhVHqlUt7ggR1Hsl/tkvTSze8pI1P6dGp2XW6AnH1iayn
 yRcoyT0ZJ+Zmm4xAH1zqKjWplzqdb/dO28qk0bPso8+1oPO8oDhLm1+tY+cOvufXkBTm+whm
 +AyNTjaCRt6aSMnA/QHVGSJ8grrTJCoACVNhnXg/R0g90g8iV8Q+IBZyDkG0tBThaDdw1B2l
 asInUTeb9EiVfL/Zjdg5VWiF9LL7iS+9hTeVdR09vThQ/DhVbCNxVk+DtyBHsjOKifrVsYep
 WpRGBIAu3bK8eXtyvrw1igWTNs2wazJ71+0z2jMzbclKAyRHKU9JdN6Hkkgr2nPb561yjcB8
 sIq1pFXKyO+nKy6SZYxOvHxCcjk2fkw6UmPU6/j/nQlj2lfOAgNVKuDLothIxzi8pndB8Jju
 KktE5HJqUUMXePkAYIxEQ0mMc8Po7tuXdejgPMwgP7x65xtfEqI0RuzbUioFltsp1jUaRwQZ
 MTsCeQDdjpgHsj+P2ZDeEKCbma4m6Ez/YWs4+zDm1X8uZDkZcfQlD9NldbKDJEXLIjYWo1PH
 hYepSffIWPyvBMBTW2W5FRjJ4vLRrJSUoEfJuPQ3vW9Y73foyo/qFoURHO48AinGPZ7PC7TF
 vUaNOTjKedrqHkaOcqB185ahG2had0xnFsDPlx5y
In-Reply-To: <20260126122440.78e7ffebd5257e5ce00fa35a@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="VN/SMF2E";       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 192.198.163.11 as
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.11 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	DMARC_POLICY_SOFTFAIL(0.10)[intel.com : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	FREEMAIL_TO(0.00)[linux-foundation.org,gmail.com];
	FORGED_SENDER_MAILLIST(0.00)[];
	TAGGED_FROM(0.00)[bncBD22BAF5REGBBTFA37FQMGQE252LFUI];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	FROM_HAS_DN(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_NEQ_ENVFROM(0.00)[dave.hansen@intel.com,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	NEURAL_HAM(-0.00)[-1.000];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail-pg1-x53f.google.com:helo,mail-pg1-x53f.google.com:rdns,intel.com:mid,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 15F978D1F4
X-Rspamd-Action: no action

On 1/26/26 12:24, Andrew Morton wrote:
> I see that b505f1944535 prevented a Xen warning, but did it have any
> other runtime effects?  If not, a prompt revert may be the way to
> proceed for now.

Yeah, that's fine.

At the same time ... KFENCE folks: I wonder if you've been testing on
highmem and/or 32-bit x86 builds or if there's much value to keeping
KFENCE maintained there.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/dc5326fa-955b-44fe-abbd-ab1bf0675529%40intel.com.
