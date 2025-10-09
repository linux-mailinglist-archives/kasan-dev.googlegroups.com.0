Return-Path: <kasan-dev+bncBD53XBUFWQDBBHHZTXDQMGQEI5ZJUAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 71C78BC83A0
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 11:13:02 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-4d6a41b5b66sf30721441cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 02:13:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760001181; cv=pass;
        d=google.com; s=arc-20240605;
        b=VJVGRPMMkoYnt9P9dzGlH8CEZo8yZIYcrABTXTSmukzfPJ8IoEc9EWBAy19J6Jkf4l
         4VNBN/JbAhm67i14w5kZn1r3J7IwO0TRW59KhgBfgiNjobS5tntnsL4R9YdTfHDnKk7l
         UEqI3aniIATcpjtfGNN0fycZM8wzQlqyWg1fTzSV7JOBpE1Rgxq6HJjK5qtWJxqgw7+x
         gGXvrwJZIdHtSWr+vBlBxrzeZjd2lRkItIVusWSk3ZDHuZyrYTcMMxp35G52FDbbvqD3
         t908/qVdY7+cMweEVgWTiM1g/X1MzLWTy9elO39jIYiyD/Wiy+DKRYEwASlSB0Eg4g6l
         KE2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=TlVbyjhUowRaZSNioQZIabeYG//B+ay6SGfBtPoUs7E=;
        fh=r9BQDQaWBctXnIiRjhjVBl3Yc2X1UfV0AL+bwzUX/fQ=;
        b=QRpjLDsOBeKMf+iFHfQ9E5L6YuAm1o9st4D9inwjm66qLGXh0+rqQUV1C5qUVLFhHF
         u9ToxlGE9KESZY38vXpvIpTjohVSnh25FaljhaYAkfQyQxvspYvYPE4q4BcywfUVC6/d
         W8gpaylOPUc1C6/30Ql7xHAgxLSSnE5+IjfAQSzpEyHf1nP469DnCSR62UC6rKc2i4yL
         SmN4RbgOaxaH/9dJcDTJUhQxsMd6ZvgOK14VCHd8yBSwkcEKGQnV9GT8jLPhlUiIdCKA
         JWP0MjUKzJlFE94Z9zuv2jN8LvootTqluZUIzauKGuiDpRkI0ydJKY5JcQ4FvilRf7xH
         3cGQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=WO+qCJ5Z;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760001181; x=1760605981; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TlVbyjhUowRaZSNioQZIabeYG//B+ay6SGfBtPoUs7E=;
        b=HCXSn2AyOAUJH8/rLtLqkF0IwPn3RvD9mxc+sdpRuWcnp7LOoOfquLT/4pslXeu7za
         FDy0nWDGB4xiP274uBrFsVg9F+IlCkKCZPJ0qvF/rwCIdZPS2Y0sq/Tch+c2iT0y7nHe
         dt4uWxMduR0V1+JAiPoH5THX6x1AmRSCc3NUWExObh3dZwlZxwXEruUpIkQP5p6ox+58
         5oxws3hUokxUVEV2yTBlLdp5KRWiB7eSl4LW1CwnmHSYvuDZlpGeroBDvAP7QvDVBN6w
         +96fYHUOKdLROHNaH7iVekmdUfxNguZFPxvIb2e4qc2w8OFag0D/4+9Ovnjo2U8gRJwD
         7ZkA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760001181; x=1760605981; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=TlVbyjhUowRaZSNioQZIabeYG//B+ay6SGfBtPoUs7E=;
        b=c1zWbt97UJHEinphnSbIENzK9Feb5lk3lEXpS1tupyFd/Kmh3HTJCKBJg/NDfl6otz
         Hh9VFjFnplvYXL8DeIGx1BSpFoYy/7ecstLkDDqqKIWsMR050XmlI4dPpBAXzJJDwIUW
         9hWKQz6ymznwSQDJylhsdSebRQ3AbYubWmTyZsWAjfO7sHNyNqowCawk3qQaMRKGNKvU
         e2nzlwXu1Zcmj7Uj88tQapjCnduFmWgqVTiB1aJSbUOnDn6R6ShT8uEiD+CMMyfSnlyg
         mpfC5z6HuvyYu4ZW8HYoHorV4jh19Q1vbpkFH57CH+h/n8iNiJ7v2yT6H6CNSPpQ/e8n
         6wzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760001181; x=1760605981;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TlVbyjhUowRaZSNioQZIabeYG//B+ay6SGfBtPoUs7E=;
        b=c00V9CMZn86Nf9+p5RQ3O8+MV/pxeNxcBO3C73fDf0nzpxvie4jpo2WNJYiwt8p+9u
         z2qWqfA2znJObgZP12aJYF1317HNiRberRzKfM8Ck8KYRzeIYVKq/jDNNUza69CSQGU+
         RY6I7pQJRd4U9klSMeBLNxlx4+8oAMkg6ybmze4gipqZsFMh0U02VfN8FMhgU5tSuG1U
         1dpagJXcT52aXYKFz7hCXLjQtEeVGIQAUHf5DjOKCHPQsPxLisOp+cMwxx36YuZ+piKQ
         C7sjZDhWkLTpxArwOu7Uc8P9rMoYzn16dmM+hGClCGAFtW1Cj+fVENL1cgEO+LdkKhHF
         uOVQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWga3qdB8u1U+x7oruPQJ5t/EVD2IAVtcsreZLHdfvaSnXYT+kJQQCNm339CkVYJwNdsIagZw==@lfdr.de
X-Gm-Message-State: AOJu0Yz0fvXc79knCYP/yMT9EBtaXCTq32kI+DQYI+dgV96TjtK/UDEi
	SO66qZSTn8NQb3ku+OXCoyzt48Qf00AAU3TtUfs/7heg3/5L5/9JL4bM
X-Google-Smtp-Source: AGHT+IF3FbuMfjkacojf/Yb3EeBcl5lA92y7rh5dAsdWY8Igwbx2UjHWwTVr02dqdMiJhG50fJcgJQ==
X-Received: by 2002:ac8:630d:0:b0:4e6:ec09:f178 with SMTP id d75a77b69052e-4e6ec0a1d9amr56481801cf.45.1760001181127;
        Thu, 09 Oct 2025 02:13:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7JtxgG5LlsR0uQ7MoXQLB245iFrpTM+iQB5+fSRimcWA=="
Received: by 2002:a0c:e74a:0:b0:87b:bc55:2a6d with SMTP id 6a1803df08f44-87bbc552e93ls4529626d6.2.-pod-prod-03-us;
 Thu, 09 Oct 2025 02:13:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXEPadWU8zCvQF+I79ypJ3REaAfEoscZjZT/Iung7XtBTK1FycSTH133XtW3CYgflGNgqCpu+cuU0E=@googlegroups.com
X-Received: by 2002:a05:6214:dcf:b0:78e:6248:ce70 with SMTP id 6a1803df08f44-87b2107eafcmr115846386d6.28.1760001180059;
        Thu, 09 Oct 2025 02:13:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760001180; cv=none;
        d=google.com; s=arc-20240605;
        b=Ne6RRq5TQ00SznohJ+dvK3S7+UoJvuiJ56fs9dN0OYPNhxULeVs7cG9hQr43FVNcfC
         04lZII3tMbJVbHdmo202nVql5LdsihBC7s6G7/NMi0FiOPEHoWuKBEf11Euu12Vktthr
         Ac4/Ihprfwzs/iSid6QjU4H45yE9Y83YlYmmPvnZKW/4AWR3eZ/675qCf4u9v8Teujma
         /hmg1ClEUrIU0zv3TUPeUI5XnPhLPrmatjm6jd14PufhMdX3sUf5sc05sPSRk2arWN60
         TuKKTC/JAVYUd5vci8gfMtDRMk9VbtTTKMqWTPbf7Au9CMKMTSgMh7q3kcvjTeNVettk
         kuAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=noGJIDsEGpbT4mVPtLItOHBIizt5I7YMxK5vpTBOvYc=;
        fh=qv1wHWsoOMLNdH99uohU6YUylk6cXOMTPibK6yjlIlk=;
        b=Vq57wrq01Zshzd1hSZ4I+GU4q2n1QNG6au+lN4Pklt9WwNVwVz8BUE/okXNHNnNfi4
         wo1ngCobWhdxO4wOSMquOBnhGcgHeyjCuJKbuG3h8OFc1cMb+1KNVvpAa+MjTRQSPsGc
         MHPUhd5BOWjmfo9r0j1rHuAoTrfX7z3DoVYM9Ygpp27LRQ97v0uG7iivVaTjzU/vi+Rk
         CRHHwtd0hGRMMrv6Q5g8F10fg2+8MCdihezQsnLKG1Be+1gitP0E17zIg2l5woe+6E1I
         miJZTr9fMsZcbdyozl0fkc44o2G6jZRRoOHX38ncdUyLeMb+yT4maQb3xJdjHAPrRdmZ
         W/ZA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=WO+qCJ5Z;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62a.google.com (mail-pl1-x62a.google.com. [2607:f8b0:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-87ab87cae9csi735386d6.8.2025.10.09.02.13.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 02:13:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) client-ip=2607:f8b0:4864:20::62a;
Received: by mail-pl1-x62a.google.com with SMTP id d9443c01a7336-27ee41e0798so12112755ad.1
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 02:13:00 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUSPqATchbuUNGx8vik6n7HYp9SI8xjStTAAXBGMOZA93M1xg0cwl5YdXDIkVutkPL3zZIdXm90DRE=@googlegroups.com
X-Gm-Gg: ASbGncsgAfms4yI3ZKjEOsWfq5oU3B9k2i1V5YevasaX/VBlgyeK+tntP/qtwrH72OP
	NEt9PomW9+kT8Dh0RlBc+OX3I5tOoMPnVzBlkyfSrcQZGr0sd+ROmEnxAIm62puUdqFMwRUGzSX
	dACUmCMqEIqOADHnjb8UWgFZGOiKqUK1Xl2qZ1Zc6EqACB63BBwf0AXMNzjtaUDlIEYd4z+4Gwf
	Fn+QjwG+mNP+G3ChqJ/RtELesGcuNwVZWiOfS1qvnH7e+0y76Dm4T3TQJwXZ/E5E+UgGP9WoVYf
	O3nZTnQFDg1D05AHkfxcMcrA6qP9PtAbCqAouojfg2M7fpG3W1af9a4xvy9UX9dgiHnuk35nhVw
	wKfrDI6P016XRtQ2umNmCe2cG/6cuG9qfB82gSeVd0MdaemBmu7svZoeuGtj82Q==
X-Received: by 2002:a17:903:8cc:b0:267:9c2f:4655 with SMTP id d9443c01a7336-290273ffcf6mr78713905ad.41.1760001179036;
        Thu, 09 Oct 2025 02:12:59 -0700 (PDT)
Received: from localhost ([45.142.167.196])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-29034f3de4asm22026565ad.92.2025.10.09.02.12.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 02:12:58 -0700 (PDT)
Date: Thu, 9 Oct 2025 17:12:50 +0800
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Randy Dunlap <rdunlap@infradead.org>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Jonathan Corbet <corbet@lwn.net>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Juri Lelli <juri.lelli@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Ben Segall <bsegall@google.com>, Mel Gorman <mgorman@suse.de>,
	Valentin Schneider <vschneid@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Namhyung Kim <namhyung@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>, Ian Rogers <irogers@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	"Liang, Kan" <kan.liang@linux.intel.com>,
	David Hildenbrand <david@redhat.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Alice Ryhl <aliceryhl@google.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>, Rong Xu <xur@google.com>,
	Naveen N Rao <naveen@kernel.org>,
	David Kaplan <david.kaplan@amd.com>,
	Andrii Nakryiko <andrii@kernel.org>,
	Jinjie Ruan <ruanjinjie@huawei.com>, Nam Cao <namcao@linutronix.de>,
	workflows@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-perf-users@vger.kernel.org,
	linux-mm@kvack.org, llvm@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com, "David S. Miller" <davem@davemloft.net>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	linux-trace-kernel@vger.kernel.org
Subject: Re: [PATCH v6 23/23] MAINTAINERS: add entry for KStackWatch
Message-ID: <aOd8kvWYIROq99vx@mdev>
References: <20250930024402.1043776-1-wangjinchao600@gmail.com>
 <20250930024402.1043776-24-wangjinchao600@gmail.com>
 <3913273d-12e2-426f-aec7-263b7f49008a@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <3913273d-12e2-426f-aec7-263b7f49008a@infradead.org>
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=WO+qCJ5Z;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Fri, Oct 03, 2025 at 01:50:43PM -0700, Randy Dunlap wrote:
> Hi,
> 
> On 9/29/25 7:43 PM, Jinchao Wang wrote:
> > Add a maintainer entry for Kernel Stack Watch.
> > 
> > Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
> > ---
> >  MAINTAINERS | 8 ++++++++
> >  1 file changed, 8 insertions(+)
> > 
> > diff --git a/MAINTAINERS b/MAINTAINERS
> > index 520fb4e379a3..3d4811ff3631 100644
> > --- a/MAINTAINERS
> > +++ b/MAINTAINERS
> > @@ -13362,6 +13362,14 @@ T:	git git://git.kernel.org/pub/scm/linux/kernel/git/shuah/linux-kselftest.git
> >  F:	Documentation/dev-tools/kselftest*
> >  F:	tools/testing/selftests/
> >  
> > +KERNEL STACK WATCH
> > +M:	Jinchao Wang <wangjinchao600@gmail.com>
> > +S:	Maintained
> > +F:	Documentation/dev-tools/kstackwatch.rst
> > +F:	include/linux/kstackwatch_types.h
> > +F:	mm/kstackwatch/
> > +F:	tools/kstackwatch/
> > +
> 
> Add entries in alphabetical order, please.
> 
> >  KERNEL SMB3 SERVER (KSMBD)
> >  M:	Namjae Jeon <linkinjeon@kernel.org>
> >  M:	Namjae Jeon <linkinjeon@samba.org>
> 
Thanks, will be fixed in next version.
> -- 
> ~Randy
> 

-- 
Jinchao

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aOd8kvWYIROq99vx%40mdev.
