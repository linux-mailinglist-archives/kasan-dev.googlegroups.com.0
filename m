Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRVPWDDAMGQERH43W7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B1DAB853F0
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:31:36 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-4b345aff439sf18858341cf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:31:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758205895; cv=pass;
        d=google.com; s=arc-20240605;
        b=A2CdIHVIvaYnyQnnHh7LFGLcOCWvufsX3ShRtwMNOd8I1l7roTrgbo/tTOjy1Qss67
         q9ROP1g35A9zzqexugsoomPYHcSCIdYbGIqLHHKB2/bglcR3eBi1F1fICwxD9XWiCOgc
         OAFG5KYcuJF0ZJdbOVIFVpJ2icbD888dVMk5WZceOYkkPeaKA/s5vzZdy8pwGse3T3Nk
         qWAmV7a8vIf8rW0XCheHypGw34L+DqFQL5PhkaNsE91MZIS+DFkn+81oQHUZxYE1R6RU
         9TFaaVIXRYTxGTprlvxMduW12PmMl4p+PDnpK4psbGlHycQ+KA62EHgnwitqfGBU3xK0
         zQww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jdXh4aqassUjmb3ywA6yFMIKW4fiD2QCPujiTLirH9s=;
        fh=4ORr6TN/YkSyJOT0f+joQoRw7tcP/Jm/xyRIQi326tQ=;
        b=W9+lFEoXnJTNfjqo9tFlViH8PsDSaSf5wJ3CY95ApBUT64ugs53rlQZyTh5ZEcMIsF
         3hzZRsUoFeWFYz/LdlSi2ezrktQPgfvLLgWBInimRHOcs9ljhrrTyj0fyGM3KONMh4Zj
         GbPb1f1iHybV/uG/GNxmz74oyqL5YvqP/s3xfdJATf2AwYXv/bLGGOvNSEsvgBYTguPy
         HPnek7YxC3z0YD51Alk76puQmiDQWJyQd9LcSfY9bA97D6zhU9rZMa3ucE9vJKk4moVu
         F2UG4aA7yOKo2Ea3LvuOLXWE/uJleWLeJDZ4IGuUvw+eWquKxaFWhyK/FyyobOK+Io8O
         NBaQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=BqsrxAJd;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758205895; x=1758810695; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=jdXh4aqassUjmb3ywA6yFMIKW4fiD2QCPujiTLirH9s=;
        b=tWknKPRcCNegYvVJKscstFGbgczKKfpl3akdR66tPuj+ZZUlyyoJE9vosT0EY7SOkT
         ZcGq2mVXOz13QpFy3LtxMpAlTDUTF9XrZEs0bF1NvIE7naM+kWQkRjLp9k3t7H6FM/Hq
         ZBCvXPdfouS5mV07at78KFGdpuxEI9vrHNcMNpUAb4TZrKy6gb4EFU41b3ZXSY9ejqK1
         gmulyoiCXVjJSAiA2tWjgE3Wjcawtl88QgGZuleXsaCdZQs3y9cjOgF2Wr3pOh233MDB
         e2It5qyBbfSzPHY5W0IY18gjqac8sctWo5l6i5qdUkRngnNzdDAQ8a+fhlQ3dzBSoKS6
         j8Bg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758205895; x=1758810695;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jdXh4aqassUjmb3ywA6yFMIKW4fiD2QCPujiTLirH9s=;
        b=koWhQsw+2kNLzcI3ksR+Q3fQGdy/YmRfrgiWrbFowNuLaiyTVGv125UHnipTyHV5J3
         5KQfnA5tqV2nFRFExDn4fU/JzDCxrs2U036TJYNGiiSNSopF69jI5SwpjMBavcDv+W7C
         jluWwFBcfUifkUhbJQ+63GaeGIQIdW0idj3fV9rj5FeoLtPQpkHOLeOnJn6pXSelhNP9
         mFhiRRS3DyY+vQJiSiI5y6XSHdGrJeN7D+sHoK1pxUs0X+zVewXwr4cgZKxedVmPY+yj
         wIncrVR/VGLZs8NF9cqnAkgya4QLaNdH8l+zcthr4K5mybJJHhGbo8XYr1LJv7oSY/e/
         thtg==
X-Forwarded-Encrypted: i=2; AJvYcCXLAFAxz8qGAYBKfXUSKIuaYr2UpK0Tz8E7478lfDmXI121iuLFdkMy/us+apy8RrKv3yDrAg==@lfdr.de
X-Gm-Message-State: AOJu0YyCCBalMJ2b7Z0XPkUOdrjgdNVlwPxRP9ZsIi6RCGeYPNUlf7QZ
	9+EnJo+vCg5X17Ni81+V9cFzHnMyaCvF6ruDLLtC+DhbNsGVJEM0U/su
X-Google-Smtp-Source: AGHT+IEmiPMfiprcrB9UKk7QyGHDY71NCJON7qJxuHiAoTvxoNEkvPeiuvb5oCJwkSJEj9k1WjTokQ==
X-Received: by 2002:ac8:598e:0:b0:4b7:a951:21cc with SMTP id d75a77b69052e-4ba6ce6795bmr71755731cf.84.1758205895220;
        Thu, 18 Sep 2025 07:31:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd56sqv0F1CWr32SDyL744QARLtD8NQUZ8qJXFOrziua7A==
Received: by 2002:a05:622a:1116:b0:4b7:ad20:9381 with SMTP id
 d75a77b69052e-4bdfe510bd7ls14343401cf.0.-pod-prod-01-us; Thu, 18 Sep 2025
 07:31:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVf/BkaN22gEtdliTTr2gfUpjVUcsGHOxy/Km1lPg8s1FLZmcJiCV6eGouBU0o/HIWYvVv1yQKAfTU=@googlegroups.com
X-Received: by 2002:a05:620a:2a08:b0:7e9:f81f:ce80 with SMTP id af79cd13be357-83111e2c10fmr655023185a.86.1758205893879;
        Thu, 18 Sep 2025 07:31:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758205893; cv=none;
        d=google.com; s=arc-20240605;
        b=IjpLki6wCkR9fQXByE/JD4NweCmw4Xxf8MgVXuLbh0z1yfdga8tpnq+Jkp8WYRjmGo
         RvHnG3M7rKu3wEpaL2zbZbxVBKmyNcyBZIx4sOAdooTwDfRhLuQmsXyGB1piO7ylKU3N
         hlaYmjucEeE0NIPy9i+a8U26W/f8JIoG9Qd33veh4jTBGkvcGmAUEXDRNkmGXdgogxQo
         ytW9B9KwVFx9YTVngXtfHO/jleCZShZglfhkXjZtMy/rFECPL/nFR5ux1WfA5qf6saBi
         RTUoyeYGu8JDE64otBVwUlVbk39f12g8f6L0x61sZi4w8kFp4/QU+SwRsvmK8vv/YIEt
         Abxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=x7wpgOqV2jwxbf7nUbBy2XlSiAc50BZhVeubzU1uvBU=;
        fh=jaK+vj6T1+tgoq93yRzUZLP4+N+RXZ2t7moJoagBJ/A=;
        b=blApffgc+ph70p3S5JaqgLy/SQcveu36Tq0g+TFGAe/1rwCe2CucSs6UpnvY0pBpcv
         aPaIwzrLEWnDQsw4i3taleqeOp7BuNJnQhWPHe5Cf3FiKm/HsGAUCUExxR7Py8eY1S4R
         hR04I4lDKTvS41bk+sJhWSYX3K8BLHaIueJd4RC533s3GD+ulfA5wPUemkEd1jgLAedB
         PJb0ErRtdlG6+3Q0Xj+EF8KA3zBOokWKBrJZEt5UzMMFFme92CKVxdAeE965iFAjuZG+
         pJq3iTJnfAdsLVFQGyIzrFc2pKYtcgVMOvbI9IulwIa1t9u/AjQDNwXs/Bh859QasjwJ
         9Gxw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=BqsrxAJd;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102a.google.com (mail-pj1-x102a.google.com. [2607:f8b0:4864:20::102a])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4bd9f71f276si1289251cf.1.2025.09.18.07.31.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:31:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102a as permitted sender) client-ip=2607:f8b0:4864:20::102a;
Received: by mail-pj1-x102a.google.com with SMTP id 98e67ed59e1d1-33082aed31dso342108a91.3
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:31:33 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX1IMIC7fCHOvMY5hLTDBRVK7hgtWnavuSvpKX2XYCCu3PBLrpAYSUHvibKFZH1K8cJt17dn0lf47k=@googlegroups.com
X-Gm-Gg: ASbGncvkApBFDAjsU5/8jC1KOMzDMthkG7eVznlNtxPaa9xGAQiw5YyhF7wRBFZxtLR
	SIW3sU7RFuypdGZFmteqAYjykHivvoeYNfZ/V05yQO7XQaRXWgqjPCqhCwFwHuwFWXItPBB5t6A
	7VCb1NmyIK8AhWT9F6fFVLc60jzkGzskZom8ICePMJmNwbngPt487X0U9KlRd5M6rgly3vVImxa
	kNTQV/8lGs2Dpn2IiY9kEdPXiycZTanlPsjiWktPmj3LSiVtn87/WqdJAn2MA==
X-Received: by 2002:a17:90a:e184:b0:32e:b2f8:8dc1 with SMTP id
 98e67ed59e1d1-32ee3ee55c5mr7425841a91.10.1758205892532; Thu, 18 Sep 2025
 07:31:32 -0700 (PDT)
MIME-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com> <20250918141511.GA30263@lst.de>
In-Reply-To: <20250918141511.GA30263@lst.de>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 18 Sep 2025 16:30:55 +0200
X-Gm-Features: AS18NWD0SUeFqGV9WlY2IdwTn_KEVlrUb6EWkUXQGUd586AZF2O57bI6Ojf1TCc
Message-ID: <CANpmjNN8Vx5p+0xZAjHA4s6HaGaEdMf_u1c1jiOf=ZKqYYz9Nw@mail.gmail.com>
Subject: Re: [PATCH v3 00/35] Compiler-Based Capability- and Locking-Analysis
To: Christoph Hellwig <hch@lst.de>
Cc: Peter Zijlstra <peterz@infradead.org>, Boqun Feng <boqun.feng@gmail.com>, 
	Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>, 
	"David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Kentaro Takeda <takedakn@nttdata.co.jp>, Lukas Bulwahn <lukas.bulwahn@gmail.com>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=BqsrxAJd;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102a as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 18 Sept 2025 at 16:15, Christoph Hellwig <hch@lst.de> wrote:
>
> On Thu, Sep 18, 2025 at 03:59:11PM +0200, Marco Elver wrote:
> > A Clang version that supports `-Wthread-safety-pointer` and the new
> > alias-analysis of capability pointers is required (from this version
> > onwards):
> >
> >       https://github.com/llvm/llvm-project/commit/b4c98fcbe1504841203e610c351a3227f36c92a4 [3]
>
> There's no chance to make say x86 pre-built binaries for that available?

Not officially, but I can try to build something to share if you prefer.
Or a script that automatically pulls and builds clang for you - I have
this old script I just updated to the above commit:
https://gist.github.com/melver/fe8a5fd9e43e21fab569ee24fc9c6072
Does that help?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN8Vx5p%2B0xZAjHA4s6HaGaEdMf_u1c1jiOf%3DZKqYYz9Nw%40mail.gmail.com.
