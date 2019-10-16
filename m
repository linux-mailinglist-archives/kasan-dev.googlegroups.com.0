Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXUGTTWQKGQERNM4CEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id CE00DD8FE0
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 13:47:43 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id z128sf23401695qke.8
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 04:47:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571226463; cv=pass;
        d=google.com; s=arc-20160816;
        b=dU4XkgC+KXeEpR/3x3H9HZxNCsR8TYrYK3Fq+B5HOZEvsL2tF8bTBht0fvFjeeVIXQ
         onOCMlwrjUcNg4qolK4nXgUNGWb4LjhKDGeKjz4SIQN/1OHZ/+KYjV/9D0pf9LxeRe31
         0JPVCbA8Am/3aBbgIOPtJitw6KGoBmUbbWN/L9XVaGV6hhZp4dp6Oa2FL3bJJX3sUGHT
         /H6EZitnEqxB8mZ+/yaW7C4XtOqyjX/gdSKw1nhKMdGu7nMg/IjYKqDilJmWg0bQR9bg
         YD6OReIVuqx+NaabO+67r/QgCT+Za0S3Hxx8fa2hkkXipaonW//seNJEDotwk+R3O/nK
         kQ4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Wp8dioZrJ2KkUrxUiqt8l2qzm9KsBY1+n3IDvILo1IQ=;
        b=LZDNn1VeIbivskT0gpSqnXWNaQha7siq4a/BNwVx5PcxLxVOKiv9XowfnIWrz0TBbb
         qZ+hzjMxG9A2ickurqlL8iJ8iglT+auSZd3UGG18G8qdgwTK+/8DkpqR5u+NJ8gVbPSW
         Mt44ZqounIFJb+TXANxb3FYUXa27yTX4+IJb5P3WzS9aJKmtDa66uNALs6FmIImzBQvm
         thP6I+Wp0KshhZ5qQtWZLnurDyo8qqWSinNsUGgBjWRLC6RbRJuExha5l46nFMWfgT5Y
         lWCHZrdtUB3GRzQRT5taAPly5gI9aCPA0KyCU3tAgTe5JtBkSP8uWFan5lHsK2Kve/iN
         N5Kg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qxYBTI3s;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Wp8dioZrJ2KkUrxUiqt8l2qzm9KsBY1+n3IDvILo1IQ=;
        b=RlIvDK+5NQ5ykP3zwiBTqa5HFIPonjmllz979CE2yNdUOPCedo4z2ZIGPnfBjaNY48
         xjowZMkKhQ0UD0hneDQCr8dOC8/BLvD/XqSpwHHhKdqAQJYyqlrqLcDsAWPo4CCeCcWI
         DZzjFgq3ygLoDPSRaH/wlddgnXsFmOXqF9p6o/Old0UQo4GPSdAYmEFbX4Lp3gpw9NpV
         ifzshjfLYRUqCgwzXzcAg4n6jZb3jOonbDPB7OhI6AUFbVlyeBQxu0Y2MZiKIRcF+SFu
         N85ztzfC4a7vUrAp9cOk/mXywEVYU1PONcNYIAFDCYbSFqy/oqj+JGJH915ze/gwd+oO
         YF2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Wp8dioZrJ2KkUrxUiqt8l2qzm9KsBY1+n3IDvILo1IQ=;
        b=Y1AmR6MNMbQBEKrtL5C9+fl7WBEyuKpnO/anYQj7+f/+00+nwCZsSUcYJ9V06X3Yj8
         gPih9D2Kl4eTxLy6EAR0DCODBxsJOz/hdj4gLQmcrERTDJqTDQZuNLdTFc+UsNpuc47v
         E2uaHLsbqmf1Rk4awM2UhzJHMQ5pOvAvaq4em315NE9yCs0+BaS6nv8WAfnJKCfzIMBw
         hCjddRVBjd0YGFapa/RJ1bo4FAz/6Hvv9QitYL+lxA7bEOVQ2D8jNyi9OxZQz0Ao/2rt
         BNMLddAjrRz60ye5UnfbpSa/vp7Swe0o0LDD5M1nPPBGR7TJt3P7G6IxjFtbZr1bBhk5
         lKiA==
X-Gm-Message-State: APjAAAUqWzJ9umVdDC2mItvBtttdZBHUavT/yF0jaaGKGzDMV0HbgP7Z
	XpgINoEw/w7DEhM5mBlPxFU=
X-Google-Smtp-Source: APXvYqwtRSF8V/E55zbEJJUtlgBPfVVhLB0JufHatLoFkw+g0W/l7fSZzJQC0m2apUXu4AMjh3QDKA==
X-Received: by 2002:ac8:363c:: with SMTP id m57mr44197671qtb.290.1571226462875;
        Wed, 16 Oct 2019 04:47:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:1a73:: with SMTP id q48ls668656qtk.14.gmail; Wed, 16 Oct
 2019 04:47:42 -0700 (PDT)
X-Received: by 2002:ac8:534a:: with SMTP id d10mr45022685qto.349.1571226462599;
        Wed, 16 Oct 2019 04:47:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571226462; cv=none;
        d=google.com; s=arc-20160816;
        b=l4oVZaaoUKcQthKivOISrOEyXdBGcNNe40EZACXCX+O3pEIhfAAQNAxQo1u7ODCTK7
         YL3KyRmPsUEAE6aHolZtYaiAyItMYGQEBg5iDgHHJdRBEkS2r63zef+YzBeW2BmL5M/a
         KOjd6KWDL6jC1Bh5ww6AeB2gNXI52IyGf30QuAFQ/xNIf9Rsj7FMT42GiEJnbLjMpo4r
         4EP+d2LyOXjQlPRc/IRzk+SkCTg/6fJxwEyqBLcO3nuWbgnNkyJNlXz3JZEPLJ5T+TOi
         bI/NliQ2niU3F2+LVp7+jzyLqA/UhhLHizljd0ZbA4oE1pxHJnVxynBAovQjbvm+9RIY
         HKQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4FFfdl/5HhwgogS+uQMVCmerpDy+QFALdziBFwG47Ho=;
        b=UfSNEfaryq83UTGsVgBQ2wxve6T3btKz90Rv5mbnukY5B4oxzuG58nTDwarpBlecDw
         e62kwFs38EJyleyMYoeeiuwgvW7rsS42gIqwYFDVqVAwZ1IlFhPi5ad4GGywBM9Yh1c9
         eQnaPyyWSSNRvGjNnYRPyh21l7C0il0p4X5idGSWdF3ucTaSWJPck8iV3h4W0MMFPmgg
         RyCKi5yQxJlWtfj7B0yTEBmbhPPmSEKBs4v/dh2GuIzLo7xLy4mIM5wzcuGHuLaR4Lsh
         GsozS8ZYFWeycIiUv81ixl8rI+gfTkZIaDzrIaX+s49n6naNCYNQbTVAvayrR1sXBIo5
         2tOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qxYBTI3s;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id v7si400981qkf.5.2019.10.16.04.47.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2019 04:47:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id 67so19856602oto.3
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2019 04:47:42 -0700 (PDT)
X-Received: by 2002:a9d:724e:: with SMTP id a14mr34065885otk.23.1571226461723;
 Wed, 16 Oct 2019 04:47:41 -0700 (PDT)
MIME-Version: 1.0
References: <20191016083959.186860-1-elver@google.com> <20191016083959.186860-8-elver@google.com>
 <20191016111847.GB44246@lakrids.cambridge.arm.com>
In-Reply-To: <20191016111847.GB44246@lakrids.cambridge.arm.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 16 Oct 2019 13:47:30 +0200
Message-ID: <CANpmjNMww9EX_WqAfWbQk8VG=DghLL7f=Otsx2=bs5sLh-VERQ@mail.gmail.com>
Subject: Re: [PATCH 7/8] locking/atomics, kcsan: Add KCSAN instrumentation
To: Mark Rutland <mark.rutland@arm.com>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	Alexander Potapenko <glider@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, Arnd Bergmann <arnd@arndb.de>, 
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>, 
	Daniel Lustig <dlustig@nvidia.com>, dave.hansen@linux.intel.com, dhowells@redhat.com, 
	Dmitry Vyukov <dvyukov@google.com>, "H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>, 
	Jade Alglave <j.alglave@ucl.ac.uk>, Joel Fernandes <joel@joelfernandes.org>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Poimboeuf <jpoimboe@redhat.com>, 
	Luc Maranget <luc.maranget@inria.fr>, Nicholas Piggin <npiggin@gmail.com>, 
	"Paul E. McKenney" <paulmck@linux.ibm.com>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-efi@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=qxYBTI3s;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
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

On Wed, 16 Oct 2019 at 13:18, Mark Rutland <mark.rutland@arm.com> wrote:
>
> Hi Marco,
>
> On Wed, Oct 16, 2019 at 10:39:58AM +0200, Marco Elver wrote:
> > This adds KCSAN instrumentation to atomic-instrumented.h.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >  include/asm-generic/atomic-instrumented.h | 192 +++++++++++++++++++++-
> >  scripts/atomic/gen-atomic-instrumented.sh |   9 +-
> >  2 files changed, 199 insertions(+), 2 deletions(-)
> >
> > diff --git a/include/asm-generic/atomic-instrumented.h b/include/asm-generic/atomic-instrumented.h
> > index e8730c6b9fe2..9e487febc610 100644
> > --- a/include/asm-generic/atomic-instrumented.h
> > +++ b/include/asm-generic/atomic-instrumented.h
> > @@ -19,11 +19,13 @@
> >
> >  #include <linux/build_bug.h>
> >  #include <linux/kasan-checks.h>
> > +#include <linux/kcsan-checks.h>
> >
> >  static inline int
> >  atomic_read(const atomic_t *v)
> >  {
> >       kasan_check_read(v, sizeof(*v));
> > +     kcsan_check_atomic(v, sizeof(*v), false);
>
> For legibility and consistency with kasan, it would be nicer to avoid
> the bool argument here and have kcsan_check_atomic_{read,write}()
> helpers...
>
> > diff --git a/scripts/atomic/gen-atomic-instrumented.sh b/scripts/atomic/gen-atomic-instrumented.sh
> > index e09812372b17..c0553743a6f4 100755
> > --- a/scripts/atomic/gen-atomic-instrumented.sh
> > +++ b/scripts/atomic/gen-atomic-instrumented.sh
> > @@ -12,15 +12,20 @@ gen_param_check()
> >       local type="${arg%%:*}"
> >       local name="$(gen_param_name "${arg}")"
> >       local rw="write"
> > +     local is_write="true"
> >
> >       case "${type#c}" in
> >       i) return;;
> >       esac
> >
> >       # We don't write to constant parameters
> > -     [ ${type#c} != ${type} ] && rw="read"
> > +     if [ ${type#c} != ${type} ]; then
> > +             rw="read"
> > +             is_write="false"
> > +     fi
> >
> >       printf "\tkasan_check_${rw}(${name}, sizeof(*${name}));\n"
> > +     printf "\tkcsan_check_atomic(${name}, sizeof(*${name}), ${is_write});\n"
>
> ... which would also simplify this.
>
> Though as below, we might want to wrap both in a helper local to
> atomic-instrumented.h.
>
> >  }
> >
> >  #gen_param_check(arg...)
> > @@ -108,6 +113,7 @@ cat <<EOF
> >  ({                                                                   \\
> >       typeof(ptr) __ai_ptr = (ptr);                                   \\
> >       kasan_check_write(__ai_ptr, ${mult}sizeof(*__ai_ptr));          \\
> > +     kcsan_check_atomic(__ai_ptr, ${mult}sizeof(*__ai_ptr), true);   \\
> >       arch_${xchg}(__ai_ptr, __VA_ARGS__);                            \\
> >  })
> >  EOF
> > @@ -148,6 +154,7 @@ cat << EOF
> >
> >  #include <linux/build_bug.h>
> >  #include <linux/kasan-checks.h>
> > +#include <linux/kcsan-checks.h>
>
> We could add the following to this preamble:
>
> static inline void __atomic_check_read(const volatile void *v, size_t size)
> {
>         kasan_check_read(v, sizeof(*v));
>         kcsan_check_atomic(v, sizeof(*v), false);
> }
>
> static inline void __atomic_check_write(const volatile void *v, size_t size)
> {
>         kasan_check_write(v, sizeof(*v));
>         kcsan_check_atomic(v, sizeof(*v), true);
> }
>
> ... and only have the one call in each atomic wrapper.
>
> Otherwise, this looks good to me.

Thanks, incorporated suggestions for v2: for readability rename
kcsan_check_access -> kcsan_check_{read,write}, and for
atomic-instrumented.h, adding the suggested preamble.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMww9EX_WqAfWbQk8VG%3DDghLL7f%3DOtsx2%3Dbs5sLh-VERQ%40mail.gmail.com.
