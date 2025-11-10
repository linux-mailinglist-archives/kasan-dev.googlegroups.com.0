Return-Path: <kasan-dev+bncBCS5D2F7IUIPTQ6IZADBUBGEIBWYS@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 75D95C485BB
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 18:33:47 +0100 (CET)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-641738a10c4sf1642738a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 09:33:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762796027; cv=pass;
        d=google.com; s=arc-20240605;
        b=iAfJUusx3BEjlE21fl44I0t5zFtdz0NpGgzbXQ+KoYy0eWYa2lHEjgnaB1Rw34I2kZ
         +G8uFP1Ng71mS5neHiau57KUOx4iwpb4gygds5P0AX9uGYX+aki9KL1npbiSSjyrz0uo
         DpqMWwUUt3ylf37zhTqwhSTn6gtdKQJaprXoS8WNaDVWk5Gjyw+BiWOIzhWeO/Ovvrgs
         DjChMYhBGKXVdZytC4dxs1qtNEHqTTPkdngEsEg7u4LbINxkc5g1Pks4D4nSW7UBnzo9
         G+Vc2V75v6YK2bMrppHA4wQ9Ma2yqUA0iYigr2V+MU7SywAL7CamwT6yOLONXECJx4yT
         Ifhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=K4b5w8bZFYla6z+ui+jxbJsFy4L5GAWHpcyaWPCXJWY=;
        fh=ll6kFqJbhQ8gaAB0tJpgWkzjrBDnz01YWGUSJxfqmqo=;
        b=LxbTfh3NWpTaUzoGfLLHQQiYSgsGeeyzgyRB8n71Wj585Vhf+9BY6PWFBf2cCiE3aM
         F02rf7L4Df3AKPiobi4EbEjJAiZl3Q1em66bYA/qZAorjU/DqeP0ElTciWS1vSCNJs+A
         fZRgcfY+Vtc/LBkAY6OBXvcjlB64HJEVEboswvIySexxXL7wCkfcmHtkxEf/TYk/12+q
         rSxpYqfOIOF1efQrp7qJUVSUeUoCCaT5J7EE4UFN4+H11eq3fJ55wHg+vlMbioh/gKMK
         aSs78K09kslHjBSe5Kkj7/5tT5WkP8Vif0u4Nyfe5lXcIv+xELBqd1jN9LKZYvT7mW5/
         ndoQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=hDu5eaBS;
       spf=none (google.com: willy@infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762796027; x=1763400827; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=K4b5w8bZFYla6z+ui+jxbJsFy4L5GAWHpcyaWPCXJWY=;
        b=hRTqLdznzpLrxIRvqjMJIYEX0bTJE3f9s6Zp5otEkwApf2PFo5nvEXy2r45kO9T1Qf
         u+W8bC+ycKOhw8r3giy1gsYneC23mdUV0k0AnOkXmFeYzS02p+2IF/qutgKXNCnhlPSw
         7Vv3TR+f2/mxRWd8kyTLN2NfCGDxEBSY/ae1cjoeUkJT48Q9hI1vECS+uFDyrkkV/SBv
         /KXwOzvozTYeaVPs0uLE9qtQxKUoHVR/XIbbEz3kb/378vvlVIBo/d5CBHfMYinIMBkp
         8in+dWisCuboXA8Ids+qbgjM4IAR4kDOB8Bm8cqGMlUjEOouyjGlVtI2+O9MC5no1WHm
         XY0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762796027; x=1763400827;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=K4b5w8bZFYla6z+ui+jxbJsFy4L5GAWHpcyaWPCXJWY=;
        b=XEpnRxfn/4FW6lHVDFyYdsdN4UH2BDY9rRqqZgbSA4p0lU1us8416WsPTnl/FkBSnj
         EMUKOhU3TmRXcifLgj2yY8VriMOdNnkOeP1hbAfJk3nS+r/HPWuDW/HZ6lzFZZubUpeS
         SRy+thRG7Pbf2dp/MqQMCTJyIM8ANU8vPk5cxG2aP09RojH4LIhhvyj4GjHUEfDa6Vrc
         ZZPJMpRqWl7dFDup0IjhHZ7RATj+QffO7iQ9DluN81I+AoIIXPpzsuZ5D4L7RHyFNH5H
         tywVE0xGQhHGqi6EYwuAUUsq+w8lCP8aN8r4fEmD11fzxpt5cLAcbs1MMHQCQ+HQq+TJ
         Da2w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUcaCmyVwA5MByEg7cdhknGea1Uy/3xK5jTu8FoEolCB5UIY2mdXEIfthqDxc+ohNgglWw9Ow==@lfdr.de
X-Gm-Message-State: AOJu0YyuHCqwm+4NWjS6JM388gKyGk+FjYOjfX9ivkMNxr+lAJEAJq6r
	bY80rawxlROIblG6p1M5/mdi3daNA9nIX7aB56JgljH+S48fHp4hrVSK
X-Google-Smtp-Source: AGHT+IGXmFYfvhrYI5rJoPQTcTSmLWOA0GM+thu6nRBCTmcGIcYnGVVMXxK12RT5BGUgZdsYScQaMw==
X-Received: by 2002:a05:6402:1e93:b0:640:8bdb:65f0 with SMTP id 4fb4d7f45d1cf-6415dc14fe9mr7427513a12.11.1762796026429;
        Mon, 10 Nov 2025 09:33:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Zhpj+O/HQ72+FGEJNqcaDndaLyfkgXQo/mAKmthrSp0Q=="
Received: by 2002:a05:6402:a195:b0:641:6948:624e with SMTP id
 4fb4d7f45d1cf-641694868d3ls1504203a12.1.-pod-prod-08-eu; Mon, 10 Nov 2025
 09:33:43 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXRyCJhqjE9M7RsP2hzZZOpFf1QJpPW+uqV+AjhGC1tR5bqIgKFVGUc4Qs6IUWXdFQzlkvg+AGcfkY=@googlegroups.com
X-Received: by 2002:a05:6402:50cf:b0:641:24cc:26d7 with SMTP id 4fb4d7f45d1cf-6415dc22b9amr7130277a12.14.1762796023214;
        Mon, 10 Nov 2025 09:33:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762796023; cv=none;
        d=google.com; s=arc-20240605;
        b=ezl4gVgmBXyeDKg5ysal9zF1SreWufgUI3gqtF8TROUyH8qOrofyyNxA1rKTRNBoQo
         ybGB/d4JK/vvCwxwi12hmSDFs2i22UMaEmlh7Nk/evZonAJFrermObCIL81KFSQsrZrg
         GXMjvNuheL7MjAILJv0zoDz3ap76lImqPm/SKCWpYUms0AGYYJJ+ONTW3mD1TDfDWIfg
         TLjvU/PDIrLArJ8cCdTId9OOJqiQ447Uvg9RRRQWnr84+gtnQcVw6j1Wm3PZ6IZhBCfK
         hRLR4M55cQbhPAGO/BjqEO0FLMxVxto9t3xkuZVhuYIO9CRPt7BNoGXsddVBot3Puoi6
         QSkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=ag6LW6hemevws8YrksBMYRPO4jlV1oMVj+5QJ4bp/14=;
        fh=XIwtjJpJ/aEPgY3rXhOBFX4FLeJ+eQdgGpFh/PG4wfk=;
        b=hDznWDhzl2qtHlYBP0JCAp7P/qVTml7JD7L4H/iUt+7trZXvfh6NNvqJemD0O6xN4+
         ye/jM+Ta2SBWqOt5UxgSYb/bvMuCZJZeVIqYC5OrCpwybrN7fCpMnQH3bIhlEtHqPkIc
         8aKGKOlGKaFuY754QxLjAmVQzrg8r81yKz/mwHvZYA92XYPMUSFci9/3heNN05F4drk7
         U2E0HVThPevxnyioV8PzeJWZrZwjC2C170xrqRFrj2etO6cTCj/PsrPv2DRfffbTr2H1
         Uf1a3hy4SamIG/Hn4rYtydlxuMrPcYhOt5ORZRJd8o6skKMfVZPSiGhfVKdIH2a7PrHU
         2IGw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=hDu5eaBS;
       spf=none (google.com: willy@infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6411f6f5762si87047a12.0.2025.11.10.09.33.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Nov 2025 09:33:43 -0800 (PST)
Received-SPF: none (google.com: willy@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from willy by casper.infradead.org with local (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vIVla-00000002xxn-1bOm;
	Mon, 10 Nov 2025 17:33:22 +0000
Date: Mon, 10 Nov 2025 17:33:22 +0000
From: Matthew Wilcox <willy@infradead.org>
To: Jinchao Wang <wangjinchao600@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	"Masami Hiramatsu (Google)" <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Randy Dunlap <rdunlap@infradead.org>,
	Marco Elver <elver@google.com>, Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Alice Ryhl <aliceryhl@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrii Nakryiko <andrii@kernel.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Ben Segall <bsegall@google.com>, Bill Wendling <morbo@google.com>,
	Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Hildenbrand <david@redhat.com>,
	David Kaplan <david.kaplan@amd.com>,
	"David S. Miller" <davem@davemloft.net>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	"H. Peter Anvin" <hpa@zytor.com>, Ian Rogers <irogers@google.com>,
	Ingo Molnar <mingo@redhat.com>,
	James Clark <james.clark@linaro.org>,
	Jinjie Ruan <ruanjinjie@huawei.com>, Jiri Olsa <jolsa@kernel.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Juri Lelli <juri.lelli@redhat.com>,
	Justin Stitt <justinstitt@google.com>, kasan-dev@googlegroups.com,
	Kees Cook <kees@kernel.org>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Liang Kan <kan.liang@linux.intel.com>,
	Linus Walleij <linus.walleij@linaro.org>,
	linux-arm-kernel@lists.infradead.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	linux-perf-users@vger.kernel.org,
	linux-trace-kernel@vger.kernel.org, llvm@lists.linux.dev,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Mel Gorman <mgorman@suse.de>, Michal Hocko <mhocko@suse.com>,
	Miguel Ojeda <ojeda@kernel.org>, Nam Cao <namcao@linutronix.de>,
	Namhyung Kim <namhyung@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Naveen N Rao <naveen@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Rong Xu <xur@google.com>, Sami Tolvanen <samitolvanen@google.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Suren Baghdasaryan <surenb@google.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Thomas =?iso-8859-1?Q?Wei=DFschuh?= <thomas.weissschuh@linutronix.de>,
	Valentin Schneider <vschneid@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>,
	workflows@vger.kernel.org, x86@kernel.org
Subject: Re: [PATCH v8 00/27] mm/ksw: Introduce KStackWatch debugging tool
Message-ID: <aRIh4pBs7KCDhQOp@casper.infradead.org>
References: <20251110163634.3686676-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20251110163634.3686676-1-wangjinchao600@gmail.com>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=hDu5eaBS;
       spf=none (google.com: willy@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=willy@infradead.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=infradead.org
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

On Tue, Nov 11, 2025 at 12:35:55AM +0800, Jinchao Wang wrote:
> Earlier this year, I debugged a stack corruption panic that revealed the
> limitations of existing debugging tools. The bug persisted for 739 days
> before being fixed (CVE-2025-22036), and my reproduction scenario
> differed from the CVE report=E2=80=94highlighting how unpredictably these=
 bugs
> manifest.

Well, this demonstrates the dangers of keeping this problem siloed
within your own exfat group.  The fix made in 1bb7ff4204b6 is wrong!
It was fixed properly in 7375f22495e7 which lists its Fixes: as
Linux-2.6.12-rc2, but that's simply the beginning of git history.
It's actually been there since v2.4.6.4 where it's documented as simply:

      - some subtle fs/buffer.c race conditions (Andrew Morton, me)

As far as I can tell the changes made in 1bb7ff4204b6 should be
reverted.

> Initially, I enabled KASAN, but the bug did not reproduce. Reviewing the
> code in __blk_flush_plug(), I found it difficult to trace all logic
> paths due to indirect function calls through function pointers.

So why is the solution here not simply to fix KASAN instead of this
giant patch series?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
RIh4pBs7KCDhQOp%40casper.infradead.org.
