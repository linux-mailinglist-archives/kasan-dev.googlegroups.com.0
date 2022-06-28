Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDN45OKQMGQEWBO45UI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id B472555C06C
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 12:55:10 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-106a48f2df7sf8269697fac.16
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 03:55:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656413709; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZoYk9OrCN2g7YN7sO//fQZqCMtPNHei0dYi/1p10FJ0+rveHkglnKc/W1PCqxN62nQ
         b+a9QqUsuQTn+VQdI3BfmYHVHY4jkNQfwtX5MOSAjtEgnowoMdDn3lC3Yz97+hsWV+LQ
         FcC6H2Luuwgts3CIHsi03uWiXdPrcVWD6ajFDKpWs8/VhzQgBuC/GQDl5D2PwX1FEaSs
         /hp097EQ5lJ3SfhSDTnvuejIzS8sdZa84Q6T3X3NYZWs6O9eASCtNlLpv9VDxBXgrnqD
         t1EBTV+Ld7lPw8sGVBB8iD03bNVR5l+NU6F2/KbfArLKCdNfcPxt3olqiqZkFtWzzG16
         39iw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=MVJKJXJNOC6pmMozpPlfzBkVAoLOltsePExaTendU4k=;
        b=NLrma8O/V4mIy3z4prhL4bS46XK/jH5qhlrsQcHOa5m8uNVNKcvsDRDtDQGUT1YSNu
         o2JXFuSqqslDaGxlZf83xmEcg2Wz+RwMBKwpTDfwbUAgHvKwfAWG2tC3Jc+NsQN1iOVC
         kt2YrjEYj91DyCJdb1A3vD4u2XOqxQy/xwaZN9z4pBZoDgL2eKeoqbFSjNqnUvLilS1T
         9pcDhOtUCZt2ZluOFDBGbZ21ZKWrtCN43PaZ+h+jAr+MgurJYaemYyoKXzJBorePjvbN
         gX+tQDMSdIuMEcrJP/4moLWdr8225IQDKu8ChKulkIOwUUfjUtWrcsUjUbe4mHlOs4eu
         9j+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=SgjVnFGo;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MVJKJXJNOC6pmMozpPlfzBkVAoLOltsePExaTendU4k=;
        b=NRaGznotR/bZO6A3Q9MynNevSHv1slgYYYwHvtyDiiD9Y2bubq0F3f/+ZUKYnyyhku
         ilOIIZ3EbFT6ngtCe29CT4COSeHSz3ETCW/rlqJ652sI1j1QreTpVj0xq5dEtXOmBjIp
         cRtv9PeZZVEo9XTcsZS9SaitfUIezh2OOMgvGM16gMAVuhQV8n7Ygykco44/JhyuEJKB
         Zwvd+HyX1Rmv/H9QjPZgdKjJVcFWOiWIajCS3ujfRwOtZoHVnHpPAOvUCa+LFL01tWhO
         y1jqu+Ifmh539lKzH3Ngp3SE8OfdlK4+ykeodM2LAgrSa4WT5yopfpBDx50JzseX+X9t
         AUIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MVJKJXJNOC6pmMozpPlfzBkVAoLOltsePExaTendU4k=;
        b=JV9eLRK2guoEIrnMfaPm+rEPrhiiRLKc5vTJc1+bZcLf1RarD67gSZ83/kQPCyQVld
         P4rohTZJPJ9Ft8iHLllj892d4ngy4S0DzsSaoYeTqklM7a6TWwtICKQvqmdGfAWUModY
         /D1i2FIbPJ6MT8bUxilBCnVd4g9sdU9HrSfbxgCQ2jb/Wx4u/p9quMB1ur8M1TFLI/0A
         +USzBiqt6wtoYgBUCBq4fGUJ2gkjddzrLcZwm37W3av7JSdD5/mvLzTa17aegF8fD5zM
         v2eoX+u5AcoaVaiaLls6cJi5lHVFtTAHj0jOoWCMxuwTP3VXCR4FTTRy3XV57osapRVj
         Xghw==
X-Gm-Message-State: AJIora90t+k6w872HS8/HsjzR7jmwzK2+J1/sgUUejZkzPlcXVQ6tVTQ
	5aVfNJQQYJpyj3+b6Jjrc/E=
X-Google-Smtp-Source: AGRyM1v5Ykc6aKbrn9oek9z3aK384d4KCqhpGMaljfKCn7vCOY2/cr90xYKYvxHRUkpTy0EEKDnHdQ==
X-Received: by 2002:a05:6808:1153:b0:32e:b45d:bd74 with SMTP id u19-20020a056808115300b0032eb45dbd74mr10944146oiu.259.1656413709314;
        Tue, 28 Jun 2022 03:55:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:12b0:0:b0:616:af74:ea9 with SMTP id g45-20020a9d12b0000000b00616af740ea9ls2118250otg.5.gmail;
 Tue, 28 Jun 2022 03:55:08 -0700 (PDT)
X-Received: by 2002:a9d:7997:0:b0:60c:5ac6:cdf3 with SMTP id h23-20020a9d7997000000b0060c5ac6cdf3mr8336107otm.17.1656413708870;
        Tue, 28 Jun 2022 03:55:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656413708; cv=none;
        d=google.com; s=arc-20160816;
        b=TfZ61cbxWDVNeYotzYTWUWWWZYtiieK07hbcXCaJK0CtU8iVqMbq+AnyMqaZhSgunc
         tWKLaMrPX3usCbBQdftgn19/Nd3NjSO8RGvxIMEFJS8NmQuKvG55Ou5H3zeXUcxnBWez
         3a7rF1PPxutJNe7PgwBhkQFZW5T7YTCWj5y+3ZGF2o/Mo3qLvtC10tP07jeKFXwZsqd/
         0FYGtnjsGJXOXek5yO1h0SXJdS8Gs+lsJRInBG4RNL6+Z/lAnFPbwBM0aqJshJvfT01Z
         El/+itQKajBYhogSFY79DRo5S+sZNX8w5VAO39AXF3+uwBASlbu8iMsMGfe717BVhOkP
         TuFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Bx+nn3bN9pkcTAPrSO8SXuVhJpjdYzH6Wim9ZDKKiAY=;
        b=eNSt1lMqnMRpyrPcjiqVjK9r3Wj9aSZEI6q3/GcnIrYMqtdqzTUMywaIv0uAAYMaY4
         +usmhOquz3DehijH2eRHhWBiIS2kw0l5kW1rfm7l+kYk9PTxEwKfF6hElIYG5uxMtWdg
         DAS6+NYpRsONtAlD2hYg91eyd1iw0EIEy8xxQaaow9dcKjPcnUNfV8Ay2MR+6DXMGxth
         uCK8tOOLzcVFUy9v8n7CC0kBbxdDfxrrOM/bRQxovgQ07cCwIzM8jVUO8DGgbj1JFFFZ
         QlYfx55HIE2BVe7cYVQNfLPu37Pl97b4sG2sy71P2Hh67fg6DZSSmctQLEdFdC0yZukL
         L6PA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=SgjVnFGo;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112c.google.com (mail-yw1-x112c.google.com. [2607:f8b0:4864:20::112c])
        by gmr-mx.google.com with ESMTPS id a32-20020a056870a1a000b000ddac42441esi1844752oaf.0.2022.06.28.03.55.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 03:55:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112c as permitted sender) client-ip=2607:f8b0:4864:20::112c;
Received: by mail-yw1-x112c.google.com with SMTP id 00721157ae682-3176b6ed923so112388377b3.11
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 03:55:08 -0700 (PDT)
X-Received: by 2002:a81:1a42:0:b0:318:3915:57d7 with SMTP id
 a63-20020a811a42000000b00318391557d7mr19561304ywa.327.1656413708510; Tue, 28
 Jun 2022 03:55:08 -0700 (PDT)
MIME-Version: 1.0
References: <20220628095833.2579903-1-elver@google.com> <20220628095833.2579903-14-elver@google.com>
In-Reply-To: <20220628095833.2579903-14-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Jun 2022 12:54:32 +0200
Message-ID: <CANpmjNPapZ9p3dSB1RC-cBoJ588XkRxJRzbhxx4THLZ9aWsx=A@mail.gmail.com>
Subject: Re: [PATCH v2 13/13] perf/hw_breakpoint: Optimize toggle_bp_slot()
 for CPU-independent task targets
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Frederic Weisbecker <frederic@kernel.org>, Ingo Molnar <mingo@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=SgjVnFGo;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112c as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Tue, 28 Jun 2022 at 11:59, Marco Elver <elver@google.com> wrote:
[...]
> +       /*
> +        * Update the pinned task slots, in per-CPU bp_cpuinfo and in the global
> +        * histogram. We need to take care of 5 cases:

This is a typo: "5 cases" -> "4 cases".

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPapZ9p3dSB1RC-cBoJ588XkRxJRzbhxx4THLZ9aWsx%3DA%40mail.gmail.com.
