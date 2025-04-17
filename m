Return-Path: <kasan-dev+bncBCCMH5WKTMGRBNHPQPAAMGQE5XA42YA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 777D5A91C9D
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Apr 2025 14:44:38 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-306b590faaesf532908a91.3
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Apr 2025 05:44:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744893877; cv=pass;
        d=google.com; s=arc-20240605;
        b=fWpcQjORKOxQE0G3+PFt2vhi5HdysJtxM0F6f3MzJOC0fcKi42Vz3OYLTdW3ZOPLyc
         uXhKH9SASqNamE+4zSl6x0o1JDC+C1VgNdGwi/veyFCtuWHtQ0QeO2v4a5A/9RbxgvTp
         oHFExBL9tkwK17ILWUtj94GKqm0gJbmE9nGzOCMG7N7oxz7wjTZcUU0TyeZE8LTFt4vI
         75AXudalsWlEf7yAQ5ptK81YAQj1ZAgvvkNEdV3dfFK8f2AAX5lrJIGItEL2CT0U/pp7
         V+RuLlbYJMRswUKOe6SqSsyNkjTtBIHYYE7Gcetcz47aMn9BWXYk6JdcqHfT4Y9C8ndU
         dXfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=peKlKIGoJBhjQAfp39mPx1X8IIOUt08KIyvtSARS75c=;
        fh=ZHaN7IvbyRU/ogZIctV+6QmlWTaepGc6durLCzMDGiM=;
        b=c1JeYKiq3mJW6Sr7WUjBObjhDfHEJEkPkwN+mNc1DNK/znM8m9Q6m27yE9QyHO3fRH
         4eqfpsomY8wjmjeJhcqKad7p324r2fszA47it5EtzVrKrWVqvHa4KPihubh7kzqxlBAn
         Qv/VjNF7umj8wGFQK7dyb0kNgjywh1Eyam6c8vQ7BgDxbg2wDqhL3b8/t5JHmhflV6sT
         KAfakPSTCLp22PijKVy7BnYv5Y1wDIbwWpPPLmbtq7KkPhldi6d4z8/3pNYR68RJEhiE
         9DfyD0r9MXTrF1Tgfa1Krs8uXhE4SnqqchjWdZgFMxK8TP7ryY8ijgHrn873M2heqDE7
         H5/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tXe69tsP;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744893877; x=1745498677; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=peKlKIGoJBhjQAfp39mPx1X8IIOUt08KIyvtSARS75c=;
        b=jPkj64fFv0z8lY5DwNj+8Qs07ZfP5V8IYj//7hm32QrIhGztVTKNzuuQrORoWKzGPs
         S707J9pbA64T6pvu/tPUQXQ6yg82B+BrkmbRzy5LVriS8tmUIrikEzHuYOj0aQ703c0f
         zNyYme+KevaYsLgSnNEckYp35q8LIDi4oGjkvMXrRWYgy815Na31LwIbWitEYp/fngWG
         f9SDFOkbl0rpNqU2JBS40kegVf/OzWAa/Mf8Mwq1qx/JL90WT+ZEAyvYpyAZXdbT7ywK
         C5WlI+T4hJ/n0q9s6CL2oR6LKuNlRS2YMdts4rbqjb7szsmIoSd4OkYRAZLcmGwuwZSg
         i9bw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744893877; x=1745498677;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=peKlKIGoJBhjQAfp39mPx1X8IIOUt08KIyvtSARS75c=;
        b=UfbYhsEgVPEmakySiENcSUYr73GkDeIJo/g+bQymRq/ZFXel7CNblZitee7noYrICG
         fk4tTxgAEwAIpoEx2cIq92LPEQ4kpDHBNgnoWJXtHr24fhA79O/VW7oo/vyuGcYVrFK/
         rurcaVSud9ppJUPEqPIzu0rChQDpzh1wV+7peP6HEBVxFTKk9PIecN++YVRdBo4/PlE/
         OmhVkqhEmKlHf3Y8boH/3lrQ/GtML2eFB/TPMcJGz4ofrjgyMLHaHVcO0+71felzvi5T
         /H6ao6wwI9gJqAJrcFdtsNAwgwap0d9ey4zy4yOh5BH2Lh/8t9llO8++6EbCjr36jjyw
         GzQA==
X-Forwarded-Encrypted: i=2; AJvYcCUONEQdNgsEmF01NYzKhBzIMCO9YeCAHSqXQjvKr0B087r1VzEu6T6j/Avfg4ciT9GJlXj0hQ==@lfdr.de
X-Gm-Message-State: AOJu0Yxy0iREz+znmawSyihfx4bI9C3/wEAyzy+epPimnoth15Qg1bl3
	wIbuYMLBENagLMGMA1ZUfN9d8wkb28MkMZrLgF1ZBsmRdyemHkZx
X-Google-Smtp-Source: AGHT+IFjpoJwnmwgepPVv9OKMoyBFABZIB/E5uJANfyyLLiY1WEqyTeNm3VovFbFCdfhzZ6soidV/Q==
X-Received: by 2002:a17:90b:58ce:b0:306:b78a:e22d with SMTP id 98e67ed59e1d1-30863f306aemr8602816a91.20.1744893876519;
        Thu, 17 Apr 2025 05:44:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJ/TfVJ26QEbxFslhjDIQu26OkPXttNlSKUCYhRaeqB1A==
Received: by 2002:a17:90a:7f8b:b0:2f9:acfc:8eaa with SMTP id
 98e67ed59e1d1-3086dc491f0ls685727a91.2.-pod-prod-07-us; Thu, 17 Apr 2025
 05:44:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW/AGii0CRJqG8EiKROp1UjQtUGvnvtuljDRFdNDOzaFJpKRxYjRdPqcXXLyaTvX4NkiT23pmBbc0Q=@googlegroups.com
X-Received: by 2002:a17:90b:5146:b0:2ff:502e:62d4 with SMTP id 98e67ed59e1d1-30864173113mr7087850a91.32.1744893875146;
        Thu, 17 Apr 2025 05:44:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744893875; cv=none;
        d=google.com; s=arc-20240605;
        b=Ok77+VftBoxmELglMFhrFvVUda4MbmIYj31jDR3xO2WEHecRspBAzQObkgkxDQxJj0
         x+EDcrlPRI0M1qya9SZqFBAs208KI56xeVKrWafA3SXspuQ1Z98aCDxeZfKCaeEos3BN
         c57M4M3EP3zssn5JLwwyLB5zSivkC753B8jc9tvHSadj089SCKxCFFBJN1vhkAMUTfcb
         6ToOe4Hj+qbLzpF9JdrHEkOmpo5CcgrNMbMI1IBvFqIaAMcuRZCNd+pM9M/4AIu769V7
         OKx8s8zh+SjxAcC+doothnSAHkTHMt8y6SUo9gHbCrm9aiqtp6YNUw+nG+jd0mv3y8Sp
         ByLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/Q1QqZcrRDm+z4zKny6B/oOLvOzzSnBzA1wNvjUJPDU=;
        fh=gq7JvZlBhL606BZSKP1tQydwm87Bk8PQnGOJKuEwc2w=;
        b=Aci5oM8WFLS1UezeeWHW1hFQUXFSG/1h8B/NzS8bSydsgFtm6q8PML+XBYo61/3tuv
         hmqSJd+Tq7WgJOi3yBS74hqSpCJ25Rn7KdmQJ02mhk0KS92uKJ3fz/eiuAtvAhkVIDcV
         /NdSUWruq2bUZG/gup/JsU09MLWohUOq5P/a9fFgtth3aKAVlbNEtqCG1NbQZ/8zOM9D
         vFaMLQNd/pWVmVFlaFpifgyf5OaSiuY78WwurElJTaC5XXItm+1HevGdBoDoM5jzkgHd
         AWcSrNR+snIFlTvbfnaF7Mph3JESZV6u0qqyipt22CstcYI7SjvJhxxCmLLwdtU81wuJ
         lCYw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tXe69tsP;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf33.google.com (mail-qv1-xf33.google.com. [2607:f8b0:4864:20::f33])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-30861370c41si134773a91.2.2025.04.17.05.44.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Apr 2025 05:44:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) client-ip=2607:f8b0:4864:20::f33;
Received: by mail-qv1-xf33.google.com with SMTP id 6a1803df08f44-6eb16dfa988so7598466d6.2
        for <kasan-dev@googlegroups.com>; Thu, 17 Apr 2025 05:44:35 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWlvTZmtx8DuMcXK80ltur76OAm0qgemAed+Uo8o9645z0bHPtGQvBinj1nSoVnRLSYI7x3Bd7FRIQ=@googlegroups.com
X-Gm-Gg: ASbGncuL/l6+lpfqzMxOfItDsSawe1Nm8K3/AUuofMpEJ9QY/gl9IJ5Dx9sgEnzYQ/m
	WTity9+EQzlBphktMqjYeSvBarLCpSD4uhCdP4mdikw0PNQ7Q5hmkKx4oPl5f3YGnOByXxiBrwA
	PVL8094V0D34Wt1PYL+6h1d/DB9Cod5Bt81jLQq/erKeCq09cYZzcK
X-Received: by 2002:a0c:aa07:0:b0:6f2:bcbf:1030 with SMTP id
 6a1803df08f44-6f2bcbf11a4mr17778526d6.43.1744893873997; Thu, 17 Apr 2025
 05:44:33 -0700 (PDT)
MIME-Version: 1.0
References: <20250416085446.480069-1-glider@google.com> <aAB9sUllq/xR/Maf@hu-jiangenj-sha.qualcomm.com>
In-Reply-To: <aAB9sUllq/xR/Maf@hu-jiangenj-sha.qualcomm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 17 Apr 2025 14:43:56 +0200
X-Gm-Features: ATxdqUHPHhj8x6Foqmh22Sf3Tnz5IYfxqO1r6Iz-bl_MdJoEp9NcRi1P5468ovk
Message-ID: <CAG_fn=WyvDopbDN3YrrUzS-aUgbVKTDRv6D5vArnQbSkp_xB6Q@mail.gmail.com>
Subject: Re: [PATCH 0/7] RFC: coverage deduplication for KCOV
To: Joey Jiao <quic_jiangenj@quicinc.com>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	Aleksandr Nogikh <nogikh@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=tXe69tsP;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

> > Below are the average stats from the runs.
> Is there test without trace collection? Is bitmap only enough?

If we bump the bitmap size to ~16K, it should be enough to keep all
the fuzzing results from a single run.
We haven't experimented with it much though, because syzkaller
currently processes coverage as an array of PCs, not a bitmap.
Changing this would require a major rework of syzkaller, given that
the positions in the bitmap may differ between different machines, so
we'll need to maintain a reverse mapping between bits and PCs in every
executor.

Such a mapping could be implemented on the kernel side on top of the
proposed patches, once someone proves a need for that.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DWyvDopbDN3YrrUzS-aUgbVKTDRv6D5vArnQbSkp_xB6Q%40mail.gmail.com.
