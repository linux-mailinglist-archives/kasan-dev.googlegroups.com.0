Return-Path: <kasan-dev+bncBCCMH5WKTMGRB6MCRCQAMGQEPPPUMSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id D72286A9941
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Mar 2023 15:17:30 +0100 (CET)
Received: by mail-oo1-xc3f.google.com with SMTP id e137-20020a4a558f000000b0051a14b3d779sf952654oob.15
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Mar 2023 06:17:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677853049; cv=pass;
        d=google.com; s=arc-20160816;
        b=MjHM/4CUFDKVPkSc/xfJQiNjIbtrT6bYhxGqEbmbLe4zCHjQo1PPQ+PEe0BlnXvaHO
         Oob8KxVXBCNT5IW0LalMU8Med9s19bEPRAJUuirVKTjfL1h4vILm2VfhcQVP1bM/jIo3
         fWJzS56sKmmEF5rDdEWgFgnD6jH9jmVZ9alHU8bun8i8CfP9D1WJIS34I9y3HYhIuYS9
         GQosjMtiFOdbKEcA/a3PVF7TGoTF6Cxo2w7+8on7G8E8S4HfMu5MNFS343p/g5VWfld1
         RgX6QkObu/rHwRb2uE0ZgDUZHDWOu9yOKb+jZCF+YPmOiaM1U6a2WpezIjmBHPicEixG
         JCqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=CW+tWH+nx3KUgvOsr9072a9mt6H8b8NrS/dOj+Du/SM=;
        b=juKjbpSlfl+XRjTRU/H5EozknoZdeC+hpl7JbPIajAvCUf+k9EaTJ6kxJsydCbkVEl
         xptlYzW6m8LswsyZ/YINfH2GmDIU614y0jwHektDx7eh17SAraP7UZcv2tNFLEhMdU4g
         3Z4iA4aAlt5XhH+V9Z9HoRF2jFwW4PY4+aO02XJtVcxaM5lVYJ+VHoa86H0v7mcejaWy
         /1an5q9sJtyIB7AehAV5ukte5lpar/dk27Y69Kuyd4zmlX9+5/NUCnFEoj5b/pdCG6Vz
         fTgXzwxBgeUMLLOz5D/cF8dkL1IeXsKwlqKRU2d7Z+8TEUUIPyMBrI6OsVMxcLmuTOhr
         Fu+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FEDTdi5M;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::12c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1677853049;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CW+tWH+nx3KUgvOsr9072a9mt6H8b8NrS/dOj+Du/SM=;
        b=kiXzRZetdnix33sUc/Gv+sM6jPeH1bNmHydcySEcez07IlwhWguNaSIP5nHplpZZnz
         Rkl8zn9aiMfUQoIEfTbpCOLSicoOjjaZ68BY5Nyzl3TtdHoSLurHUxJysRnSanX66nYm
         f9tCTFVoOuHLRWAq2KVISQ/2DS4GIh3Wx91qA92xX1vbxsJvFH6uQUo3m6pQKobr2tU5
         OINsyuH3LAeVvd75gsXZoLmJRUA7oYkFkms/wapV0euaJ2ucR01K2LZQw9YBMmeyBxjN
         ha5UXZLMDPhGj1lKn62OVTbhhq4znagUVS4dzsRb2D21D+Zy71EX67BMNL++Mlu9kK4q
         McCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1677853049;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=CW+tWH+nx3KUgvOsr9072a9mt6H8b8NrS/dOj+Du/SM=;
        b=K6g+N/L1UzZvD8lToWbHhnVPMGuM4PQHW7wtNxf00B2CtNBByrwgYxWX2dUXLriMIp
         3D3Twbf1sPwpBzPMs80GeC4Jeq+ox1b3YYv/0ehmNf9OCASE8nDvlnQmIL+DZ2LVIA5s
         Aj6NSEWZNbashuhJ5qIDdaiGrbAfDRhwR6+lQoyHXqyljEaW4bI3MVfN/DFUpTkk72Sv
         wTw3WqAEn44+r8r/k+w5Bw+XdcwM5+0R8X/aIg0Auwsklsbh+yKFUpyBJIiBzYU/T+2U
         4ROW++gtbcq2vctqRrAJCS+ntOXY5RKfGfSJx1VBCll1OVVjDm5a/jPdk8fgk5UL+rII
         OG5Q==
X-Gm-Message-State: AO0yUKVtEpiaAzaXCWJUveGWo0M0yoZwW/RbVyzm8NfHGeoEv6/h5mXw
	5/2jSFOHxtK5ssmqElHOoDA=
X-Google-Smtp-Source: AK7set9hL8ds2oAxm/x7rJnT9vZSkcFVsn7Q49qdEGDNdOJZglHrlbdmGr6hfP780ikpCH/YEKsv1A==
X-Received: by 2002:a05:6808:2098:b0:383:f981:b1e5 with SMTP id s24-20020a056808209800b00383f981b1e5mr2923921oiw.5.1677853049403;
        Fri, 03 Mar 2023 06:17:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1e9c:b0:661:b84b:eb5e with SMTP id
 n28-20020a0568301e9c00b00661b84beb5els680713otr.3.-pod-prod-gmail; Fri, 03
 Mar 2023 06:17:29 -0800 (PST)
X-Received: by 2002:a9d:7105:0:b0:684:d9da:6ead with SMTP id n5-20020a9d7105000000b00684d9da6eadmr518779otj.17.1677853048885;
        Fri, 03 Mar 2023 06:17:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677853048; cv=none;
        d=google.com; s=arc-20160816;
        b=eKJMA3mrX2qHJey+RA1r6iKKKpB1oUACLQn/HlYamfj1a9FOiQGk+YxcSdMaMfQVWR
         9b6k/wf29UM49OEMe+xiyK+fqG2MEpN8z0YOvEJ8LskZJ174LxN8VDKChkr1irJt3tMA
         O8cq1yqLUIjS20CtnXs+0GUuc9rZJ0aTZjy0FWh49kEsUgaZnzIYcAmY9NQolBCM5cpt
         DplbJyU+DqZbrZGLLihj+VRsaLNv8GpT3FuBktF4zm/AfXgYF52Nrx/brxpc/ylEexpS
         kzLdwoRAd0yTRGZc8WCwUPfBp3TiX4ZummoRQnTzZzuA3bc8SAXGsdXMJlLD6JvAEV/5
         c2rg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0B3hgicuXjM7bBAtA4QLzoXhHV0rOr+vQWIDTCOLWjA=;
        b=xyd3+eQ1tR7mVwiEilEqtLZGQVT57V7GGa+xyxX3czkySwsyo3S8vw2m51baFmNVOs
         JdNJ6ORmaSfRt3YhHWUkGOfYb7EwTqpYYUzP8Gcoe6L+5Hfokecc5/SiE+O0O2Jmkt58
         8bOhW/WV+ytPo43fd9QF2J3nSQGmAnCgjatUZfYdwa8tV2ITug8iF1mfWA3A8nCBEuZh
         /t+BZMPP5paPyLSclaRxDv8feOHMcsekgjnfL2TK1tNlDY8fCyJxbkMduqno3iUtigMd
         zl8i+4JBjVWDcyVWmW8a+/194JnJqm2AqNPyHzTuP15kbXvqFSPy4iMYviOo1v3SkGQ4
         4Y5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FEDTdi5M;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::12c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x12c.google.com (mail-il1-x12c.google.com. [2607:f8b0:4864:20::12c])
        by gmr-mx.google.com with ESMTPS id d1-20020a056830044100b00693cf8eb076si147951otc.5.2023.03.03.06.17.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 03 Mar 2023 06:17:28 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::12c as permitted sender) client-ip=2607:f8b0:4864:20::12c;
Received: by mail-il1-x12c.google.com with SMTP id z5so1708203ilq.0
        for <kasan-dev@googlegroups.com>; Fri, 03 Mar 2023 06:17:28 -0800 (PST)
X-Received: by 2002:a05:6e02:130f:b0:315:9761:6965 with SMTP id
 g15-20020a056e02130f00b0031597616965mr917889ilr.5.1677853048407; Fri, 03 Mar
 2023 06:17:28 -0800 (PST)
MIME-Version: 1.0
References: <20230303141433.3422671-1-glider@google.com>
In-Reply-To: <20230303141433.3422671-1-glider@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 3 Mar 2023 15:16:50 +0100
Message-ID: <CAG_fn=X45qBJKgaZ4xVN=DHwDTYG7HzUb5kTwf79Rs1aJ-f9mg@mail.gmail.com>
Subject: Re: [PATCH 1/4] x86: kmsan: Don't rename memintrinsics in
 uninstrumented files
To: glider@google.com
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, tglx@linutronix.de, 
	mingo@redhat.com, bp@alien8.de, x86@kernel.org, dave.hansen@linux.intel.com, 
	hpa@zytor.com, akpm@linux-foundation.org, elver@google.com, 
	dvyukov@google.com, nathan@kernel.org, ndesaulniers@google.com, 
	kasan-dev@googlegroups.com, Kees Cook <keescook@chromium.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=FEDTdi5M;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::12c as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

This is the second version of the patch. Sorry for the inconvenience.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DX45qBJKgaZ4xVN%3DDHwDTYG7HzUb5kTwf79Rs1aJ-f9mg%40mail.gmail.com.
