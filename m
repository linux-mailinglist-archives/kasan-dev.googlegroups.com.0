Return-Path: <kasan-dev+bncBDJN7LGB5QHBBLFJ6HFQMGQEWWCV3QQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id oDwvK65UfGnTLwIAu9opvQ
	(envelope-from <kasan-dev+bncBDJN7LGB5QHBBLFJ6HFQMGQEWWCV3QQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Jan 2026 07:50:22 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63a.google.com (mail-ej1-x63a.google.com [IPv6:2a00:1450:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 51F27B7B38
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Jan 2026 07:50:22 +0100 (CET)
Received: by mail-ej1-x63a.google.com with SMTP id a640c23a62f3a-b8720608e53sf194306966b.1
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Jan 2026 22:50:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769755822; cv=pass;
        d=google.com; s=arc-20240605;
        b=la40Qp0lb4X91i3BoUw6mpwUZxqxmjTf5ZZl0pMOnGpS/8+szdRKPkvr9o+rkIFMJt
         khEmxmjjK/djLMvW0MPtlwccCFhNwGxvel9dAB3iKABUzvIM2ZivmFcIgA6c5hW41kdf
         2JjbvqBVJQ7bL6Ld65htGvu/XPveIzB3YlfH5r+PTLGVBtL8BsGDhJ6mNgM3AIG7Pyvh
         wj2e0jWhzpHt+pcvhpUNi5EGtiMlqVAU5y43UuXG3vF6aC2MqPecR6QXE6yLWJp/ozsL
         JNW510H2joa7RhutpE4GI/K2k3GjmSz5byBvFhZs0QM5KZH+XzCMX3fnsRfEd1f84hDJ
         uLsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=p7/KWuoUcfsmzJn9aGvC/xyVjQNv8k/PRS8ssgx7JO8=;
        fh=XHup759IkAtZOP0NoIEzCCYvznI6W/ts4SRoc90aFUQ=;
        b=YSDL0htqaRg5noTt5KFOL3PYV5yevM8ORjx0R0xo3XpW+stl3cHjQ+g8yrExeorwdz
         2FGFLRDfF66PjQske3WpnN7Ovf8AUMu6PsuiqAfUtpoiDh66Ls0bv9UMC1+qx1xDVtiu
         ouVST3cFSZSGfgsadBJE05B5AHrgKEcObpwL6O5yFCD/jBtWO8tDZxzoKXwWhuqLbC96
         hB5gmXFoEEdUI0LGshsZJxLYc8SRJSOMyzpN8m1gK6aKl03vwVQH0183/cOqhAYSNwXO
         jPyeiTzLrU3AmQnVub4KVIH9Gs2e7B4wWQEvbr5Z0CvewoYxBERQE9op+NhceZ63q4sg
         eYdw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=IAwRjgDz;
       spf=pass (google.com: domain of zhao1.liu@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=zhao1.liu@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769755822; x=1770360622; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=p7/KWuoUcfsmzJn9aGvC/xyVjQNv8k/PRS8ssgx7JO8=;
        b=Vcewx9Sma1+SXvxuikzD0O32W/So6zGHcGiBKbIOVpVaMgeo8YG4pmIVQWRUxKhRuP
         H8fl2bfvPfiUzikkd7QjYWex1HadWMvPGuMoEHmZdPiqqv9mhuA0oWobv5TQey4nlWG4
         3veJdqGCIIj09Ot4Z6cp/tvDFgCeLmA6zG6cpdWS6eqN7nUlKOIuIYJS1AKop5qolf45
         QkDH5/K8DK9kUNE+mRpJMaKGeIeULygez69I/Ypn6NRCt6yBaw9YQaImYwfxdq8abGkQ
         33Jvh0vDvxllhJYSu3YmTP8FxsdCVYxt2maMXdXMYvFEYgLNXYTxMZ8XzL2jCXBnftE1
         n9eQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769755822; x=1770360622;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=p7/KWuoUcfsmzJn9aGvC/xyVjQNv8k/PRS8ssgx7JO8=;
        b=FZxZx3vbFoib+5metSCULo43ZJnVmGLLLiDhgmBDR0Eio+9dkspXrfXq9Rjg2vn9Y1
         1PPM9wC8id97AZ608Qi6F+QScPTbITvaeBKIzKcCCyJyTmKkgCYcL+9n0j+BPhqeTgVk
         TOYz7QC4v7R48bwzeDq3JSF42YUR+9QPawJQ2b4sUhyC1F8zXGcKgBjLzM+5slY4d2wn
         hbrXFn6u//wEKc1wgDJIPGOk6M4cJjgswiVqjHjaa8t9XYLqKU1AQV3JnrIiSgXj0LPV
         Ns31B6qjkP6WhykjAlUarM0Q99mtC2jlmqfsD35tnxutqOz9yo32EwgmynQT2P10bX58
         taiA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVa7VBrzRbGGJsoezIK+0PEc/uV47mOprv9gkrOB5r3PwViN4hlMnj6Xj7Vc7rG3M0kb1A51Q==@lfdr.de
X-Gm-Message-State: AOJu0YxhnmlvL6LuTYWuhNoZn5wFmc/SLLBO4ANnXuBiOqMM/i+p1F2j
	4Lfwpnl6Nq8SzHYD++lPsXdBCpHm+/n5TbBqMElEs9rNd+thrGm1o5Ks
X-Received: by 2002:a17:907:1b20:b0:b86:f558:ecad with SMTP id a640c23a62f3a-b8dff5260f2mr96455366b.7.1769755821425;
        Thu, 29 Jan 2026 22:50:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+F8L5sqp6TWVCFDkvqvybP+6NtJ2R3BAYwjaDNDkg+vTQ=="
Received: by 2002:aa7:d482:0:b0:658:2e7d:4dbb with SMTP id 4fb4d7f45d1cf-658ccb50e2fls1556699a12.0.-pod-prod-08-eu;
 Thu, 29 Jan 2026 22:50:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVNuCovkRlYqq/BdqOduFiKP8YVZ7LsG56ktMoWz6pe2DbSn3WHFRXQZnjSXm7xSwxSclWbxLfQlIs=@googlegroups.com
X-Received: by 2002:a05:6402:a0d7:b0:658:e665:766c with SMTP id 4fb4d7f45d1cf-658e6657c0dmr528980a12.8.1769755819260;
        Thu, 29 Jan 2026 22:50:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769755819; cv=none;
        d=google.com; s=arc-20240605;
        b=XYeIVv3U1rxWHUsnw5yKC94LzQIB+vajyAaDgOFNe/PXHDrMYu6j/OzKrhLuk9e7KC
         YCxsxjLY4m+yoXcFp2g9pW7RU51HH4e8bZK+hyB1PsPwJMepz7sJQMA+sfiuHAMCwy8h
         O6vSxNCcVGy4/4lrE+ovnHNZYVIJgG/nUVubNfiuQJ+Ru44VHtFqlAkJYCjlCBtwqUTa
         oih1GDyhtwts80FpKbwVkssHPE+hsbkKsDQB6Yya+TrnEWG9ymX+o1c5pQeqk6FlcaUI
         7dQNdcOM2cksDQEvPeeYBfRnn6K1RxmM9aSubCjGJeCF1ONFdQJCrt1WqGiDOWTw2W78
         P38Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=27ufXsGW3skh0Zqpt+kjwDF4L/+gPwFmN+6drdfpdU8=;
        fh=KwC7Jum6N/o025Yv5BbBtrdUqOkm0+yynzCyRrsFo/Q=;
        b=E3KJC6uUitRfs5/WRDEuijlHSDexbnmQX1Bg2ToVRb5rgWlEwniHdBKNv7M0DmsFLL
         nlF0AO1E0nGlht1m+YQmCq8YB2N6bCYTMTD6olG12YBB5aKuY1EgyfSezWlb+hevYe5y
         /991gd4o6uKcmfYDmIy+JlA/kRlFEX/g26FfhhdhVkX/3ayKXw4gxFNlr5gW7n9aKTf5
         5OxnIyUDggwW/9ttqT7kcoXI1HDN8ULIWSp86fO8H5NDyoskXth97eGs6hNc3MHH7JP1
         OOGUduH0mpY6lI52gwQK+S4iRc8nFFOGMrIwrDPmICHBdwa6bbAbmlPQQ3HO3paetB6V
         PhQA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=IAwRjgDz;
       spf=pass (google.com: domain of zhao1.liu@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=zhao1.liu@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.11])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-658b4680823si159545a12.1.2026.01.29.22.50.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 29 Jan 2026 22:50:19 -0800 (PST)
Received-SPF: pass (google.com: domain of zhao1.liu@intel.com designates 198.175.65.11 as permitted sender) client-ip=198.175.65.11;
X-CSE-ConnectionGUID: /Yxx3HbcTBG6gWXmDIRbpw==
X-CSE-MsgGUID: mqXJmovTTt6yTcgM2VvtWg==
X-IronPort-AV: E=McAfee;i="6800,10657,11686"; a="81320114"
X-IronPort-AV: E=Sophos;i="6.21,262,1763452800"; 
   d="scan'208";a="81320114"
Received: from fmviesa006.fm.intel.com ([10.60.135.146])
  by orvoesa103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 29 Jan 2026 22:50:11 -0800
X-CSE-ConnectionGUID: mYaf0TBPRa2ykUmhlHu8pg==
X-CSE-MsgGUID: LrWGv+Y3RriQke2ImZiRkw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.21,262,1763452800"; 
   d="scan'208";a="208696559"
Received: from liuzhao-optiplex-7080.sh.intel.com (HELO localhost) ([10.239.160.39])
  by fmviesa006.fm.intel.com with ESMTP; 29 Jan 2026 22:50:06 -0800
Date: Fri, 30 Jan 2026 15:15:59 +0800
From: Zhao Liu <zhao1.liu@intel.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>,
	Christoph Lameter <cl@gentwo.org>,
	David Rientjes <rientjes@google.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hao Li <hao.li@linux.dev>,
	Andrew Morton <akpm@linux-foundation.org>,
	Uladzislau Rezki <urezki@gmail.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Suren Baghdasaryan <surenb@google.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
	bpf@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v4 06/22] slab: add sheaves to most caches
Message-ID: <aXxaryFUrIFo7/hL@intel.com>
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
 <20260123-sheaves-for-all-v4-6-041323d506f7@suse.cz>
 <aXsLKxukv60p3QWF@intel.com>
 <2cd89ed5-0c8e-43f8-896d-1b7dee047fef@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <2cd89ed5-0c8e-43f8-896d-1b7dee047fef@suse.cz>
X-Original-Sender: zhao1.liu@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=IAwRjgDz;       spf=pass
 (google.com: domain of zhao1.liu@intel.com designates 198.175.65.11 as
 permitted sender) smtp.mailfrom=zhao1.liu@intel.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=intel.com
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
X-Spamd-Result: default: False [-1.61 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	DMARC_POLICY_SOFTFAIL(0.10)[intel.com : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBDJN7LGB5QHBBLFJ6HFQMGQEWWCV3QQ];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	RCPT_COUNT_TWELVE(0.00)[18];
	MIME_TRACE(0.00)[0:+];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	MISSING_XM_UA(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_NEQ_ENVFROM(0.00)[zhao1.liu@intel.com,kasan-dev@googlegroups.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	NEURAL_HAM(-0.00)[-1.000];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	DBL_BLOCKED_OPENRESOLVER(0.00)[intel.com:mid]
X-Rspamd-Queue-Id: 51F27B7B38
X-Rspamd-Action: no action

Hi Vlastimil,

> > vm_area_cachep's capacity seems to be adjusted to 60 and
> > maple_node_cache keeps 32 as the args setting.
>=20
> Good to know. It is a bit larger.
> Hm I could have probably applied the args capacity before doing the round=
up
> to make sheaf fill whole kmalloc size. Would add a few object for maple n=
ode
> I guess.

Re-considerring this formula:

the nr_objects in set_cpu_partial() in fact represents the half-full
case since it was used to calculate nr_slabs in slub_set_cpu_partial().

Therefore, the maximum capacity of this partial approach should be
nr_objects * 2 (and should actually be even larger, since it doesn't
account for the object on CPU's freelist).

But here, for sheaf, the implicit assumption is that it is completely
full, so that for the maximum capacity of objects per CPU, the sheaf
approach is "half" that of the partial approach.

Is this expected? I'm considering whether we should remove the
=E2=80=9Cdivide by two=E2=80=9D and instead calculate the sheaf capacity ba=
sed on
half-full assumption (e.h., full main & empty spare).

Thanks,
Zhao


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
XxaryFUrIFo7/hL%40intel.com.
