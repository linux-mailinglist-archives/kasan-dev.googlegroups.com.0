Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIOT73EAMGQENTWM6LY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B65BC76AA9
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Nov 2025 00:52:03 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-5942fa88e0dsf754296e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 15:52:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763682722; cv=pass;
        d=google.com; s=arc-20240605;
        b=XpieJevEq8Q+m8VBZe7r5PMHKJbrsDRg8zprc39MhCG3qVD5jqz+DJz3FlDXYYOOWf
         PRaFpYrbMIovaxJ1IRH6enMZQ4V/TVvEQkmaSqT4uhY0VyJkTv3rCFYz72EgIQlXgnZ+
         A9HPhZJmZxkZ8J7y42HD2ZMcbkZsuAGWKJGO2102Cf0oYGk/zGitk5LEhU2fLj6aMzhe
         /TaSlABHtw0WnvP+XBV6jgX1gsd0nuvCQ55s6bUx9QyGRfRcRzza30ec7jidEHSV1Iwj
         0rSEJXSHTMNxbWS4YU61kNrZexTT6c5KUdUGqz/UFnILHUttSijHjG2F3Iz/DBn9gWxT
         xA2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=5JXNnlaFOJs8eXwqgvJiFaTKoJFz8Z9IxXrGgaQlLQQ=;
        fh=o0CqujoTGjV/2aXNeNNqKG1ymwnllmVxaYm/YvS8S5s=;
        b=lBJw1Dr37uXnUav87Xg/HGVmlpGODb7L7w1JPshYutU3Y9pIOyrxBMVmFU9r5OIh8w
         TWWzmEImnDeTMY7QEJo6AwlNqdeg+rsNV5VBkzyHVxC92mjbDDPjxXIYWqDPETtXrE24
         Qnk6kx9N9sjgRuO7YUF3+w1xBO0tat8vvc2Pd+fwZUej1HPKZ7ymbd8Fl62UfDUM4sKK
         BkFCzYurzfkuM4Lf3d8dV7cCKivmJg5FxmYd6YaYY//RpI6BFvYCJ1TIv+jBlFJ5+/ts
         brHOWaqmg9++SIHTzqjKMU6eW1rNHAszhdHbIcO0/bTOFl1/lchfad1wFXv4HQT2VtQF
         0gGw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HGElPhUf;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763682722; x=1764287522; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=5JXNnlaFOJs8eXwqgvJiFaTKoJFz8Z9IxXrGgaQlLQQ=;
        b=wcz1BQRmnhKfXIRNy+M2G4+ZMQlsgUTOguteGgvq5w4fnssKyIF4kSbKRT3diWBdwz
         x9cB2VSPTEhO7YiqIdoCcNY3zy+8SD7g3oegd/EIXG4upNHMz+gMYv7Islzc/z8T/dBK
         zqqF/vd+mtiR61TdW2bZuQDHH2L7R6Su+YdAa3UtYviZNwoMrAugsJZKgq8VZC0Bmkoo
         TgfiKZfBGcSmakydMnBBmSNyjOurb7LKW+RzuYyXMpMufz0fRXSLHCBh5EnYPLpaJ9rg
         KmFruU9CGbBQmYZC2iBRuuMEXOv6YuavRLMLRszzOQ/tBaEOjM0a8U96V72e7eBdzZzc
         a54w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763682722; x=1764287522;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-gg:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=5JXNnlaFOJs8eXwqgvJiFaTKoJFz8Z9IxXrGgaQlLQQ=;
        b=Fu3OiKBrE8ehri23Iudvjx5iuy9heu/NyI8ngxRJvdHaJQ6SmCi33VCupC3VE/Onc4
         ePzrwl047xLZzq4uar44O6kBPZPo4Gss6/v+NOeRmoiia93CavCKVtJ97hL9ZmMeEx5P
         jzLrGChF5eYZqzK1iaEELUGGs9eY9pjadZ6KhY3irozS7ZrVYCvM+Fg2SxWmsaa/7cz4
         17x3DUlN63yu8UYAdEm+I1tzvtBUqTKue5RcvAhiUPvtQicdnfmMpoLIFFfK2kxexMEM
         cPDBaHbcaM6zNIwoMEUdDcvq8bSDf0DXQIuQERVd7QaksFEmNEPFYw7/VV+XdLOkMLQ8
         U3xw==
X-Forwarded-Encrypted: i=2; AJvYcCUqdR3CXul1tXwwm0HQH3rE4pHdMqbCwKVWOjQ3NWGpC1GtQb3xzHxKXgKffV/A+ySLhSODcg==@lfdr.de
X-Gm-Message-State: AOJu0YxaXCSmAXBzawiBb19uwVKzkDy56NWrM5mjDptzmVWB+Ur0b0ii
	nJcnnH0btKKp6RtQJY4icKjA3CvJzb9a3QV07qzxT7DkQFw5d+YTe6rc
X-Google-Smtp-Source: AGHT+IFNZ0MZ+bk35hQW6SNxTIw6+NjOIl3jVDb7uOL+3h7l2N8yxT4lFqcZOD/AyW8cie9u6ZmWUQ==
X-Received: by 2002:a05:6512:10cd:b0:594:49ed:3cf1 with SMTP id 2adb3069b0e04-596a3e987e0mr20896e87.10.1763682722176;
        Thu, 20 Nov 2025 15:52:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aHb8mXRUVgpGgFSQfdAVo7GWcAnrhMKABKilKnb8mCCQ=="
Received: by 2002:ac2:4bc6:0:b0:596:a35d:3c0b with SMTP id 2adb3069b0e04-596a35d3d66ls71049e87.1.-pod-prod-02-eu;
 Thu, 20 Nov 2025 15:51:59 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX3tkDeISoqnKlyPqt4bhcTK3xaXuon5IL6PekFa4DPjjWNPeflaWFpu9+E8rzfyjv2OSWSycwDfOo=@googlegroups.com
X-Received: by 2002:a05:651c:41c9:b0:37b:9976:3ba0 with SMTP id 38308e7fff4ca-37cd8ea8ddamr269601fa.0.1763682718974;
        Thu, 20 Nov 2025 15:51:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763682718; cv=none;
        d=google.com; s=arc-20240605;
        b=BO9i8chdcg5h37gn99jHqpj+M60ievhm+N/ilNIchzQUOMsonhrhqKa3G9fOZ7ng44
         52ypVd075yil5OnmPAZ45p6v3OR2nr5wEGNBTwcABtk56ieMyaWJepb9b5/bI0veNNYD
         b02PXH3m4ucn6eqeg1Fgyh6nuDQ5Ta5vowul+9XW7v/mBm8oUm2K1dsxBfY5VGT5uuIe
         t/muXNG/E7WyaTXCqqWZpqrpgKInxBJlBYtPW9ovW31CYlbsUWRCwdsKliPBTLpHxWYN
         RM3tdwJIfwmmIEV22GxGahzQromxMMwG7RW2WcYgsPPhWyIQiJkebKZiyfTGw2i8z3K7
         7kMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=J9kvXa3Vdh1ip8zUpCqHWE2klTiidAnZMSHg4scU75Q=;
        fh=zXRVxyMvvKcP01TeSzhdnlXc6yHfXhjr7duX5FWKghY=;
        b=EVob17g/JiP+77bMryXKaYy7tAtx7WgSdvNL3UWooEQV3yulbNtwatBCPRhvzikpyb
         HB5RXroklLS1117AfmUWFOfgLyoABFnrN/NFIvVMZGukeLfit9aU+wQ2PrMT4XnVq/hb
         s7p7VTMu2IracauOCDHasiFNzVxKZIEj8K+Ab5CcMhBFC/MvY/dUe3oFJWS5iFdR/pZe
         XtvFLmsEidM7iD66s0Z63eQety8QudBIfmFjBdocnaMFlt2wl5RXvLV5qzoj7L/KYgMQ
         bCZ8y5AORMNB2/qHoidhZCpbBmg1ymvIHC1/038eIyfNm8XDCp5Sbi02hDRqwDy6q1u7
         XIPQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HGElPhUf;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-37cc6ba5d7bsi618871fa.9.2025.11.20.15.51.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 15:51:58 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id 5b1f17b1804b1-477a219dbcaso13957705e9.3
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 15:51:58 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWHhSOsuXZuDVS3htclDvyuwonIm95g5iNBHRTZvYhR/QuR3XrBtjzs/zCXMfPXCkvdR8qsXQUH4XU=@googlegroups.com
X-Gm-Gg: ASbGncsNxhcKpNfvILzswxQv+zcutB0Fafd3utfdx8XBagHQMzREEp8MlgAnu6LZS/H
	lwhbfAI7WqkUQGbYxSjkkELDuSk9X76BSMABiAgia52qfda4m/XnN5jSp+bT3HH6sGbsJb0skSt
	doPTP5xtwFyBDFkBuFx4uywKCFLdIwLpZV51JaGL2BVvCNYA8U7GaRo5Pldq8cSvBdoTOZMoLLP
	qps/cVrroTYliHWm3Z+y67LCm1AqS8wClbl3W5qdBqUl/nTJUC3lcNv4k7OdRNzOAWEL6QM6Bov
	wgbPjYjzTWj/X1WHpHFuvYWGnpnyhEfl1Q6VXMKlef/2HRD3E/mpoOP+GpDHor0Oe0wSO1XXDBO
	z5PqT0WK0UQX3xypuK3ubFS13k0J2WkTGBWQe4sBXLgBowujiGXQOuNRr8QFGUWEn57slnRUfE9
	mq9JsWd/hIGLj9K9Ygs9frlfSRiLYUW9QTU25993TGMTP2VKSfphufxCACixI=
X-Received: by 2002:a05:600c:1909:b0:477:b642:9dc6 with SMTP id 5b1f17b1804b1-477c020137fmr3256875e9.34.1763682717840;
        Thu, 20 Nov 2025 15:51:57 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:2834:9:3b7e:2c14:f733:1774])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-477a97213b8sm72914765e9.1.2025.11.20.15.51.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 20 Nov 2025 15:51:56 -0800 (PST)
Date: Fri, 21 Nov 2025 00:51:48 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Peter Zijlstra <peterz@infradead.org>,
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
	Will Deacon <will@kernel.org>,
	"David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	Chris Li <sparse@chrisli.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>,
	Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ian Rogers <irogers@google.com>, Jann Horn <jannh@google.com>,
	Joel Fernandes <joelagnelf@nvidia.com>,
	Johannes Berg <johannes.berg@intel.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Triplett <josh@joshtriplett.org>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Kentaro Takeda <takedakn@nttdata.co.jp>,
	Lukas Bulwahn <lukas.bulwahn@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, kasan-dev@googlegroups.com,
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-security-module@vger.kernel.org,
	linux-sparse@vger.kernel.org, linux-wireless@vger.kernel.org,
	llvm@lists.linux.dev, rcu@vger.kernel.org
Subject: Re: [PATCH v4 02/35] compiler-context-analysis: Add infrastructure
 for Context Analysis with Clang
Message-ID: <aR-plHrWDMqRRlcI@elver.google.com>
References: <20251120145835.3833031-2-elver@google.com>
 <20251120145835.3833031-4-elver@google.com>
 <CAHk-=whyKteNtcLON-gScv6tu8ssvKWdNw-k371ufDrjOv374g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAHk-=whyKteNtcLON-gScv6tu8ssvKWdNw-k371ufDrjOv374g@mail.gmail.com>
User-Agent: Mutt/2.2.13 (2024-03-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=HGElPhUf;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as
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

On Thu, Nov 20, 2025 at 10:14AM -0800, Linus Torvalds wrote:
> On Thu, 20 Nov 2025 at 07:13, Marco Elver <elver@google.com> wrote:
[..]
> > +#if defined(WARN_CONTEXT_ANALYSIS)
> 
> Note the 400+ added lines to this header...
> 
[..]
> Please let's *not* do it this way, where the header contents basically
> get enabled or not based on a compiler flag, but then everybody
> includes this 400+ line file whether they need it or not.

Note, there are a good amount of kernel-doc comments in there, so we
have 125 real code lines.

% cloc include/linux/compiler-context-analysis.h
       1 text file.
       1 unique file.
       0 files ignored.

github.com/AlDanial/cloc v 2.06  T=0.01 s (97.1 files/s, 41646.9 lines/s)
-------------------------------------------------------------------------------
Language                     files          blank        comment           code
-------------------------------------------------------------------------------
C/C++ Header                     1             37            267            125
-------------------------------------------------------------------------------

> Can we please just make the header file *itself* not have any
> conditionals, and what happens is that the header file is included (or
> not) using a pattern something like
> 
>    -include $(srctree)/include/linux/$(context-analysis-header)
> 
> instead.
> 
> IOW, we'd have three different header files entirely: the "no context
> analysis", the "sparse" and the "clang context analysis" header, and
> instead of having a "-DWARN_CONTEXT_ANALYSIS" define, we'd just
> include the appropriate header automatically.
> 
> We already use that "-include" pattern for <linux/kconfig.h> and
> <linux/compiler-version.h>. It's probably what we should have done for
> <linux/compiler.h> and friends too.
> 
> The reason I react to things like this is that I've actually seen just
> the parsing of header files being a surprisingly big cost in build
> times. People think that optimizations are expensive, and yes, some of
> them really are, but when a lot of the code we parse is never actually
> *used*, but just hangs out in header files that gets included by
> everybody, the parsing overhead tends to be noticeable. There's a
> reason why most C compilers end up integrating the C pre-processor: it
> avoids parsing and tokenizing things multiple times.
> 
> The other reason is that I often use "git grep" for looking up
> definitions of things, and when there are multiple definitions of the
> same thing, I actually find it much more informative when they are in
> two different files than when I see two different definitions (or
> declarations) in the same file and then I have to go look at what the
> #ifdef condition is. In contrast, when it's something where there are
> per-architecture definitions, you *see* that, because the grep results
> come from different header files.
> 
> I dunno. This is not a huge deal, but I do think that it would seem to
> be much simpler and more straightforward to treat this as a kind of "N
> different baseline header files" than as "include this one header file
> in everything, and then we'll have #ifdef's for the configuration".
> 
> Particularly when that config is not even a global config, but a per-file one.
> 
> Hmm? Maybe there's some reason why this suggestion is very
> inconvenient, but please at least consider it.

Fair points; I gave this a shot, as a patch on top so we can skip the
Sparse version.

Reduced version below:
-------------------------------------------------------------------------------
Language                     files          blank        comment           code
-------------------------------------------------------------------------------
C/C++ Header                     1             26            189             80
-------------------------------------------------------------------------------

My suspicion (or I'm doing it wrong): there really isn't all that much
we can conditionally -include, because we need at least the no-op stubs
everywhere regardless because of annotations provided by common headers
(spinlock, mutex, rcu, etc. etc.).

If we assume that in the common case we need the no-op macros
everywhere, thus every line in <linux/compiler-context-analysis.h> is
required in the common case with the below version, the below experiment
should be be close to what we can achieve.

However, it might still be worthwhile for the code organization aspect?

Thoughts?

Thanks,
-- Marco

------ >8 ------

From: Marco Elver <elver@google.com>
Date: Thu, 20 Nov 2025 22:37:52 +0100
Subject: [PATCH] compiler-context-analysis: Move Clang definitions to separate
 header

In the interest of improving compile-times, it makes sense to move the
conditionally enabled definitions when the analysis is enabled to a
separate file and include it only with -include.

A very unscientific comparison, on a system with 72 CPUs; before:

  125.67 wallclock secs = ( 5681.04 usr secs + 367.63 sys secs / 4815.83% CPU )

After:

  125.61 wallclock secs = ( 5684.80 usr secs + 366.53 sys secs / 4817.95% CPU )

[ Work in progress - with this version, there is no measurable
  difference in compile times. ]

Signed-off-by: Marco Elver <elver@google.com>
---
 Documentation/dev-tools/context-analysis.rst  |  10 +-
 .../linux/compiler-context-analysis-clang.h   | 144 ++++++++++++++++++
 include/linux/compiler-context-analysis.h     | 136 +----------------
 scripts/Makefile.context-analysis             |   3 +-
 4 files changed, 153 insertions(+), 140 deletions(-)
 create mode 100644 include/linux/compiler-context-analysis-clang.h

diff --git a/Documentation/dev-tools/context-analysis.rst b/Documentation/dev-tools/context-analysis.rst
index e53f089d0c52..71b9c5e57eb4 100644
--- a/Documentation/dev-tools/context-analysis.rst
+++ b/Documentation/dev-tools/context-analysis.rst
@@ -99,10 +99,7 @@ Keywords
 ~~~~~~~~
 
 .. kernel-doc:: include/linux/compiler-context-analysis.h
-   :identifiers: context_guard_struct
-                 token_context_guard token_context_guard_instance
-                 __guarded_by __pt_guarded_by
-                 __must_hold
+   :identifiers: __must_hold
                  __must_not_hold
                  __acquires
                  __cond_acquires
@@ -119,6 +116,11 @@ Keywords
                  __acquire_shared_ret
                  context_unsafe
                  __context_unsafe
+
+.. kernel-doc:: include/linux/compiler-context-analysis-clang.h
+   :identifiers: __guarded_by __pt_guarded_by
+                 context_guard_struct
+                 token_context_guard token_context_guard_instance
                  disable_context_analysis enable_context_analysis
 
 .. note::
diff --git a/include/linux/compiler-context-analysis-clang.h b/include/linux/compiler-context-analysis-clang.h
new file mode 100644
index 000000000000..534a41a25596
--- /dev/null
+++ b/include/linux/compiler-context-analysis-clang.h
@@ -0,0 +1,144 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * Macros and attributes for compiler-based static context analysis that map to
+ * Clang's "Thread Safety Analysis".
+ */
+
+#ifndef _LINUX_COMPILER_CONTEXT_ANALYSIS_CLANG_H
+#define _LINUX_COMPILER_CONTEXT_ANALYSIS_CLANG_H
+
+#ifndef WARN_CONTEXT_ANALYSIS
+#error "This header should not be included"
+#endif
+
+/*
+ * These attributes define new context guard (Clang: capability) types.
+ * Internal only.
+ */
+#define __ctx_guard_type(name)			__attribute__((capability(#name)))
+#define __reentrant_ctx_guard			__attribute__((reentrant_capability))
+#define __acquires_ctx_guard(...)		__attribute__((acquire_capability(__VA_ARGS__)))
+#define __acquires_shared_ctx_guard(...)	__attribute__((acquire_shared_capability(__VA_ARGS__)))
+#define __try_acquires_ctx_guard(ret, var)	__attribute__((try_acquire_capability(ret, var)))
+#define __try_acquires_shared_ctx_guard(ret, var) __attribute__((try_acquire_shared_capability(ret, var)))
+#define __releases_ctx_guard(...)		__attribute__((release_capability(__VA_ARGS__)))
+#define __releases_shared_ctx_guard(...)	__attribute__((release_shared_capability(__VA_ARGS__)))
+#define __assumes_ctx_guard(...)		__attribute__((assert_capability(__VA_ARGS__)))
+#define __assumes_shared_ctx_guard(...)	__attribute__((assert_shared_capability(__VA_ARGS__)))
+#define __returns_ctx_guard(var)		__attribute__((lock_returned(var)))
+
+/*
+ * The below are used to annotate code being checked. Internal only.
+ */
+#define __excludes_ctx_guard(...)		__attribute__((locks_excluded(__VA_ARGS__)))
+#define __requires_ctx_guard(...)		__attribute__((requires_capability(__VA_ARGS__)))
+#define __requires_shared_ctx_guard(...)	__attribute__((requires_shared_capability(__VA_ARGS__)))
+
+/**
+ * __guarded_by - struct member and globals attribute, declares variable
+ *                only accessible within active context
+ *
+ * Declares that the struct member or global variable is only accessible within
+ * the context entered by the given context guard. Read operations on the data
+ * require shared access, while write operations require exclusive access.
+ *
+ * .. code-block:: c
+ *
+ *	struct some_state {
+ *		spinlock_t lock;
+ *		long counter __guarded_by(&lock);
+ *	};
+ */
+#define __guarded_by(...)		__attribute__((guarded_by(__VA_ARGS__)))
+
+/**
+ * __pt_guarded_by - struct member and globals attribute, declares pointed-to
+ *                   data only accessible within active context
+ *
+ * Declares that the data pointed to by the struct member pointer or global
+ * pointer is only accessible within the context entered by the given context
+ * guard. Read operations on the data require shared access, while write
+ * operations require exclusive access.
+ *
+ * .. code-block:: c
+ *
+ *	struct some_state {
+ *		spinlock_t lock;
+ *		long *counter __pt_guarded_by(&lock);
+ *	};
+ */
+#define __pt_guarded_by(...)		__attribute__((pt_guarded_by(__VA_ARGS__)))
+
+/**
+ * context_guard_struct() - declare or define a context guard struct
+ * @name: struct name
+ *
+ * Helper to declare or define a struct type that is also a context guard.
+ *
+ * .. code-block:: c
+ *
+ *	context_guard_struct(my_handle) {
+ *		int foo;
+ *		long bar;
+ *	};
+ *
+ *	struct some_state {
+ *		...
+ *	};
+ *	// ... declared elsewhere ...
+ *	context_guard_struct(some_state);
+ *
+ * Note: The implementation defines several helper functions that can acquire
+ * and release the context guard.
+ */
+#define context_guard_struct(name, ...)								\
+	struct __ctx_guard_type(name) __VA_ARGS__ name;							\
+	static __always_inline void __acquire_ctx_guard(const struct name *var)				\
+		__attribute__((overloadable)) __no_context_analysis __acquires_ctx_guard(var) { }	\
+	static __always_inline void __acquire_shared_ctx_guard(const struct name *var)			\
+		__attribute__((overloadable)) __no_context_analysis __acquires_shared_ctx_guard(var) { } \
+	static __always_inline bool __try_acquire_ctx_guard(const struct name *var, bool ret)		\
+		__attribute__((overloadable)) __no_context_analysis __try_acquires_ctx_guard(1, var)	\
+	{ return ret; }											\
+	static __always_inline bool __try_acquire_shared_ctx_guard(const struct name *var, bool ret)	\
+		__attribute__((overloadable)) __no_context_analysis __try_acquires_shared_ctx_guard(1, var) \
+	{ return ret; }											\
+	static __always_inline void __release_ctx_guard(const struct name *var)				\
+		__attribute__((overloadable)) __no_context_analysis __releases_ctx_guard(var) { }	\
+	static __always_inline void __release_shared_ctx_guard(const struct name *var)			\
+		__attribute__((overloadable)) __no_context_analysis __releases_shared_ctx_guard(var) { } \
+	static __always_inline void __assume_ctx_guard(const struct name *var)				\
+		__attribute__((overloadable)) __assumes_ctx_guard(var) { }				\
+	static __always_inline void __assume_shared_ctx_guard(const struct name *var)			\
+		__attribute__((overloadable)) __assumes_shared_ctx_guard(var) { }			\
+	struct name
+
+/**
+ * disable_context_analysis() - disables context analysis
+ *
+ * Disables context analysis. Must be paired with a later
+ * enable_context_analysis().
+ */
+#define disable_context_analysis()				\
+	__diag_push();						\
+	__diag_ignore_all("-Wunknown-warning-option", "")	\
+	__diag_ignore_all("-Wthread-safety", "")		\
+	__diag_ignore_all("-Wthread-safety-pointer", "")
+
+/**
+ * enable_context_analysis() - re-enables context analysis
+ *
+ * Re-enables context analysis. Must be paired with a prior
+ * disable_context_analysis().
+ */
+#define enable_context_analysis() __diag_pop()
+
+/**
+ * __no_context_analysis - function attribute, disables context analysis
+ *
+ * Function attribute denoting that context analysis is disabled for the
+ * whole function. Prefer use of `context_unsafe()` where possible.
+ */
+#define __no_context_analysis	__attribute__((no_thread_safety_analysis))
+
+#endif /* _LINUX_COMPILER_CONTEXT_ANALYSIS_CLANG_H */
diff --git a/include/linux/compiler-context-analysis.h b/include/linux/compiler-context-analysis.h
index 03056f87a86f..33ad367fef3f 100644
--- a/include/linux/compiler-context-analysis.h
+++ b/include/linux/compiler-context-analysis.h
@@ -6,140 +6,7 @@
 #ifndef _LINUX_COMPILER_CONTEXT_ANALYSIS_H
 #define _LINUX_COMPILER_CONTEXT_ANALYSIS_H
 
-#if defined(WARN_CONTEXT_ANALYSIS)
-
-/*
- * These attributes define new context guard (Clang: capability) types.
- * Internal only.
- */
-# define __ctx_guard_type(name)			__attribute__((capability(#name)))
-# define __reentrant_ctx_guard			__attribute__((reentrant_capability))
-# define __acquires_ctx_guard(...)		__attribute__((acquire_capability(__VA_ARGS__)))
-# define __acquires_shared_ctx_guard(...)	__attribute__((acquire_shared_capability(__VA_ARGS__)))
-# define __try_acquires_ctx_guard(ret, var)	__attribute__((try_acquire_capability(ret, var)))
-# define __try_acquires_shared_ctx_guard(ret, var) __attribute__((try_acquire_shared_capability(ret, var)))
-# define __releases_ctx_guard(...)		__attribute__((release_capability(__VA_ARGS__)))
-# define __releases_shared_ctx_guard(...)	__attribute__((release_shared_capability(__VA_ARGS__)))
-# define __assumes_ctx_guard(...)		__attribute__((assert_capability(__VA_ARGS__)))
-# define __assumes_shared_ctx_guard(...)	__attribute__((assert_shared_capability(__VA_ARGS__)))
-# define __returns_ctx_guard(var)		__attribute__((lock_returned(var)))
-
-/*
- * The below are used to annotate code being checked. Internal only.
- */
-# define __excludes_ctx_guard(...)		__attribute__((locks_excluded(__VA_ARGS__)))
-# define __requires_ctx_guard(...)		__attribute__((requires_capability(__VA_ARGS__)))
-# define __requires_shared_ctx_guard(...)	__attribute__((requires_shared_capability(__VA_ARGS__)))
-
-/**
- * __guarded_by - struct member and globals attribute, declares variable
- *                only accessible within active context
- *
- * Declares that the struct member or global variable is only accessible within
- * the context entered by the given context guard. Read operations on the data
- * require shared access, while write operations require exclusive access.
- *
- * .. code-block:: c
- *
- *	struct some_state {
- *		spinlock_t lock;
- *		long counter __guarded_by(&lock);
- *	};
- */
-# define __guarded_by(...)		__attribute__((guarded_by(__VA_ARGS__)))
-
-/**
- * __pt_guarded_by - struct member and globals attribute, declares pointed-to
- *                   data only accessible within active context
- *
- * Declares that the data pointed to by the struct member pointer or global
- * pointer is only accessible within the context entered by the given context
- * guard. Read operations on the data require shared access, while write
- * operations require exclusive access.
- *
- * .. code-block:: c
- *
- *	struct some_state {
- *		spinlock_t lock;
- *		long *counter __pt_guarded_by(&lock);
- *	};
- */
-# define __pt_guarded_by(...)		__attribute__((pt_guarded_by(__VA_ARGS__)))
-
-/**
- * context_guard_struct() - declare or define a context guard struct
- * @name: struct name
- *
- * Helper to declare or define a struct type that is also a context guard.
- *
- * .. code-block:: c
- *
- *	context_guard_struct(my_handle) {
- *		int foo;
- *		long bar;
- *	};
- *
- *	struct some_state {
- *		...
- *	};
- *	// ... declared elsewhere ...
- *	context_guard_struct(some_state);
- *
- * Note: The implementation defines several helper functions that can acquire
- * and release the context guard.
- */
-# define context_guard_struct(name, ...)								\
-	struct __ctx_guard_type(name) __VA_ARGS__ name;							\
-	static __always_inline void __acquire_ctx_guard(const struct name *var)				\
-		__attribute__((overloadable)) __no_context_analysis __acquires_ctx_guard(var) { }	\
-	static __always_inline void __acquire_shared_ctx_guard(const struct name *var)			\
-		__attribute__((overloadable)) __no_context_analysis __acquires_shared_ctx_guard(var) { } \
-	static __always_inline bool __try_acquire_ctx_guard(const struct name *var, bool ret)		\
-		__attribute__((overloadable)) __no_context_analysis __try_acquires_ctx_guard(1, var)	\
-	{ return ret; }											\
-	static __always_inline bool __try_acquire_shared_ctx_guard(const struct name *var, bool ret)	\
-		__attribute__((overloadable)) __no_context_analysis __try_acquires_shared_ctx_guard(1, var) \
-	{ return ret; }											\
-	static __always_inline void __release_ctx_guard(const struct name *var)				\
-		__attribute__((overloadable)) __no_context_analysis __releases_ctx_guard(var) { }	\
-	static __always_inline void __release_shared_ctx_guard(const struct name *var)			\
-		__attribute__((overloadable)) __no_context_analysis __releases_shared_ctx_guard(var) { } \
-	static __always_inline void __assume_ctx_guard(const struct name *var)				\
-		__attribute__((overloadable)) __assumes_ctx_guard(var) { }				\
-	static __always_inline void __assume_shared_ctx_guard(const struct name *var)			\
-		__attribute__((overloadable)) __assumes_shared_ctx_guard(var) { }			\
-	struct name
-
-/**
- * disable_context_analysis() - disables context analysis
- *
- * Disables context analysis. Must be paired with a later
- * enable_context_analysis().
- */
-# define disable_context_analysis()				\
-	__diag_push();						\
-	__diag_ignore_all("-Wunknown-warning-option", "")	\
-	__diag_ignore_all("-Wthread-safety", "")		\
-	__diag_ignore_all("-Wthread-safety-pointer", "")
-
-/**
- * enable_context_analysis() - re-enables context analysis
- *
- * Re-enables context analysis. Must be paired with a prior
- * disable_context_analysis().
- */
-# define enable_context_analysis() __diag_pop()
-
-/**
- * __no_context_analysis - function attribute, disables context analysis
- *
- * Function attribute denoting that context analysis is disabled for the
- * whole function. Prefer use of `context_unsafe()` where possible.
- */
-# define __no_context_analysis	__attribute__((no_thread_safety_analysis))
-
-#else /* !WARN_CONTEXT_ANALYSIS */
-
+#if !defined(WARN_CONTEXT_ANALYSIS)
 # define __ctx_guard_type(name)
 # define __reentrant_ctx_guard
 # define __acquires_ctx_guard(...)
@@ -168,7 +35,6 @@
 # define disable_context_analysis()
 # define enable_context_analysis()
 # define __no_context_analysis
-
 #endif /* WARN_CONTEXT_ANALYSIS */
 
 /**
diff --git a/scripts/Makefile.context-analysis b/scripts/Makefile.context-analysis
index cd3bb49d3f09..6f94b555af14 100644
--- a/scripts/Makefile.context-analysis
+++ b/scripts/Makefile.context-analysis
@@ -2,7 +2,8 @@
 
 context-analysis-cflags := -DWARN_CONTEXT_ANALYSIS		\
 	-fexperimental-late-parse-attributes -Wthread-safety	\
-	-Wthread-safety-pointer -Wthread-safety-beta
+	-Wthread-safety-pointer -Wthread-safety-beta		\
+	-include $(srctree)/include/linux/compiler-context-analysis-clang.h
 
 ifndef CONFIG_WARN_CONTEXT_ANALYSIS_ALL
 context-analysis-cflags += --warning-suppression-mappings=$(srctree)/scripts/context-analysis-suppression.txt
-- 
2.52.0.rc2.455.g230fcf2819-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aR-plHrWDMqRRlcI%40elver.google.com.
