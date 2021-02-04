Return-Path: <kasan-dev+bncBD62HEF5UYIBBW776CAAMGQEI3FQGWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1144830FBB7
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Feb 2021 19:41:32 +0100 (CET)
Received: by mail-ej1-x63f.google.com with SMTP id le12sf3329551ejb.13
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Feb 2021 10:41:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612464091; cv=pass;
        d=google.com; s=arc-20160816;
        b=f5+3u7s/jU0FC44xf+RIr0qccDf2TMeZwy3orLjaNg9XjzxbF8iXmckkXlQTGdJTAo
         xfgF3hwnO2fx8WxL5ciK0TN/AW6MaWJKAD2JkSkYnFRqx20Vm88qRQrmduMWO0rlnrgz
         xpgAeDGEF5oCsh947C46KEIhmHr0/FtEFRhu68yLIDN+sDhQmqlAsvIQHE/K2ogqOQiN
         wUYHWAb6SD2taQI9eXWwSf1whsr+s09DZNYoCAWw6A6GVtjiMtSNiubA0N3msBdK1CEX
         tUJpM+teFdOjW5lIn4PRCbgsckDrzLeVNjx8UFuC4prMhSFrmIbt8xSUJeyavHs8vXez
         TZVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=P4o8pBnkkVWhR1tGzp1AW10uui+/p16K6E/suTyYaHI=;
        b=fK3HSTml6Bs2+y03cG2wopitXqig89gqMZ2Q0I2FP3XSK0iScB+TmgtARkxd3uLKg4
         wp39uumgoUZXnWtkvKr52yB71oyYmE3UekceNCXEzveRoOcs4NXQre+ZT7tnrbygLQHP
         5IYQ7+amtK0TtgC59hTCb5oE0sHh5a1zwBaHYkM+laeo9Nnz4CtNw2IY7St9p8JmhzhP
         nysGme7XJ9MP4RAIgSW/YOZ9IAyka2VdZoLmjN9z4jxLtGyKjTfQQMAqugU0uEPaVa5e
         USqGmTF9uFjeShxyqNCv50BSxvtkq4vKgPjKqZlY7MsfSqgtlH7Nl64KIIS2ohyaeu2O
         A9og==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@cloudflare.com header.s=google header.b=wwOS3lN7;
       spf=pass (google.com: domain of ivan@cloudflare.com designates 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=ivan@cloudflare.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=cloudflare.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=P4o8pBnkkVWhR1tGzp1AW10uui+/p16K6E/suTyYaHI=;
        b=BUlVjoQtfKitHLV7C/X6641S9UZCum3KibDJpphgfVWL6UW5RMmoQTesiDWfoD7iX7
         h6wh4kQyUKPFm13mGIJxHeTj4trxy5bMbXqATFGud9P7N4s3h9FzMO0DQY+60yxrU7y7
         OMTDvz3Q7OEJSylPLFAVhNtijFMD0QdwUMl3sljX+U6l7OIXj7jA1IuQQDHIKrlryvdk
         hXSW1KvFKbM1pbkk6KaOSgBBhADOH8NCjvymfalF30hobJEcd5ciiftLr2MvpA0s5oqW
         dZUFBfqNnp2nTCCxvamvUWEctUfMU9iYGSMzR+JvjGyTOOgfvb9VQ1PnmfTVQyVsY93q
         bQzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=P4o8pBnkkVWhR1tGzp1AW10uui+/p16K6E/suTyYaHI=;
        b=GUndgp+N4pAt6Xaw/iRIxBxMdz9U+TbCEsfUikTS/0Qy1kinO3U11lnrX8utGc6I/7
         fga1XfDHWY2J+R0J1p7D0R0GXPPyWLg1FIWgf6PmETYHdlL0igYZhKARXeyjJDblEAiB
         2bYu0Rc4/5IaIZJmPMGvRE6gn9XAO5mddubvDIYY2UWsAH5bksmpF64saHv9NGnfqsg+
         rtPsNV4FeUsPRfQMXbECd9bQbncOUvunJvyBFBz2TakgVP1jM1DOZxkcHmT2Dq8LkJGk
         w7dXP/2oN0FOyU/NcKcBF7Z/0q8CIRIiBAbjeF7N4BjCjg9tBm1KrvuRzWQvrYMFNs2A
         +TDQ==
X-Gm-Message-State: AOAM532woJmf16oLyxjnK017Y706a1MoaZ49N1r1GYtLlT9miAO/G5ao
	cIPHY4leQlGYA0pLqyrEddM=
X-Google-Smtp-Source: ABdhPJxsla6nUT8H8myMhMS5H2lU1kuIrHwMyCur1FnlL/oPyFnncfKdHhE9CRcUvWaHbOxVpknIvw==
X-Received: by 2002:a17:907:35d1:: with SMTP id ap17mr462466ejc.79.1612464091828;
        Thu, 04 Feb 2021 10:41:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:948f:: with SMTP id t15ls3385305ejx.11.gmail; Thu,
 04 Feb 2021 10:41:31 -0800 (PST)
X-Received: by 2002:a17:906:7d09:: with SMTP id u9mr447571ejo.380.1612464090979;
        Thu, 04 Feb 2021 10:41:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612464090; cv=none;
        d=google.com; s=arc-20160816;
        b=Q99dN6pvfob4C4af6pjcqJQpufOhd0hx/wmeSyMArWYIAPBsn52UKLNTNrRlndPVQb
         m6AyE3FuDP4aAmHr7pawqRjc2gNGNqlWdk+Z/zaKwycf7QJqpt4g5Vru/lD6G89V6WV1
         d9/2NaYPH92qTDeLJLUdrOA7pCRC8bg02RspRrY4b5TYbgLwD/nFmUXOcgGR7LvGZd2c
         YP4yBaXGXSA6G9ukvRLrhcTCz1GVVKgfAICFkDipFP+WUiShe4svMl0YqWc9rhQmfd4k
         5lVj8W2gZ+T+P45+V8nLeCY76IAawrZ+RTrFUS7G1ByItA7pU8g2JfJ2FtcP1wXgKYNn
         h0Rg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QilnL1GiLc35zL0JKgGqLLH0jCvxrl7AURnizvwxOrk=;
        b=NLDyIK3YkCkFekuZ6e9BfBYtc1+hwhnbWXY/QLORMbWcwwOz95Nb2w+jNdRwlF4kI+
         BQwttVSFn0bYxKwrT9Yc9XLZwy2dtKBws1e4stBgojie0OoHdZS16aAaBNBU7Slbfkvo
         qIY0NKUNkizHAgXoHHkwOyupQXljS1L9bfpmeff3CD3mqeT9zQsaCy2CfUD4ZsUEUyEj
         dSvh/aLsTxqrzzQMbUWzWnBQZwHKNkBamnN7Ti32DA5GWGB8i98vXSMm9d9gllcJLQu+
         v5fvYfg6ugyd3a3bZysXKJAtIwYvIabpKEJptgwptQabH0zaZ0EZmSe2m2Muxdqth6Uv
         hH3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@cloudflare.com header.s=google header.b=wwOS3lN7;
       spf=pass (google.com: domain of ivan@cloudflare.com designates 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=ivan@cloudflare.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=cloudflare.com
Received: from mail-lj1-x234.google.com (mail-lj1-x234.google.com. [2a00:1450:4864:20::234])
        by gmr-mx.google.com with ESMTPS id ce26si367853edb.2.2021.02.04.10.41.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Feb 2021 10:41:30 -0800 (PST)
Received-SPF: pass (google.com: domain of ivan@cloudflare.com designates 2a00:1450:4864:20::234 as permitted sender) client-ip=2a00:1450:4864:20::234;
Received: by mail-lj1-x234.google.com with SMTP id u4so4655847ljh.6
        for <kasan-dev@googlegroups.com>; Thu, 04 Feb 2021 10:41:30 -0800 (PST)
X-Received: by 2002:a2e:9b57:: with SMTP id o23mr427754ljj.314.1612464090601;
 Thu, 04 Feb 2021 10:41:30 -0800 (PST)
MIME-Version: 1.0
References: <CABWYdi3HjduhY-nQXzy2ezGbiMB1Vk9cnhW2pMypUa+P1OjtzQ@mail.gmail.com>
 <CABWYdi27baYc3ShHcZExmmXVmxOQXo9sGO+iFhfZLq78k8iaAg@mail.gmail.com>
 <20210203214448.2703930e@oasis.local.home> <20210204030948.dmsmwyw6fu5kzgey@treble>
In-Reply-To: <20210204030948.dmsmwyw6fu5kzgey@treble>
From: "'Ivan Babrou' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 Feb 2021 10:41:18 -0800
Message-ID: <CABWYdi15x=-2qenWSdX_ONSha_Pz7GFJrx8axN6CJS5cWxTTSg@mail.gmail.com>
Subject: Re: BUG: KASAN: stack-out-of-bounds in unwind_next_frame+0x1df5/0x2650
To: Josh Poimboeuf <jpoimboe@redhat.com>
Cc: Steven Rostedt <rostedt@goodmis.org>, kernel-team <kernel-team@cloudflare.com>, 
	Ignat Korchagin <ignat@cloudflare.com>, Hailong liu <liu.hailong6@zte.com.cn>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, Miroslav Benes <mbenes@suse.cz>, Julien Thierry <jthierry@redhat.com>, 
	Jiri Slaby <jirislaby@kernel.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel <linux-kernel@vger.kernel.org>, Alasdair Kergon <agk@redhat.com>, 
	Mike Snitzer <snitzer@redhat.com>, dm-devel@redhat.com, 
	Alexei Starovoitov <ast@kernel.org>, Daniel Borkmann <daniel@iogearbox.net>, Martin KaFai Lau <kafai@fb.com>, 
	Song Liu <songliubraving@fb.com>, Yonghong Song <yhs@fb.com>, Andrii Nakryiko <andriin@fb.com>, 
	John Fastabend <john.fastabend@gmail.com>, KP Singh <kpsingh@chromium.org>, 
	Robert Richter <rric@kernel.org>, "Joel Fernandes (Google)" <joel@joelfernandes.org>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Linux Kernel Network Developers <netdev@vger.kernel.org>, bpf@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ivan@cloudflare.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@cloudflare.com header.s=google header.b=wwOS3lN7;       spf=pass
 (google.com: domain of ivan@cloudflare.com designates 2a00:1450:4864:20::234
 as permitted sender) smtp.mailfrom=ivan@cloudflare.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=cloudflare.com
X-Original-From: Ivan Babrou <ivan@cloudflare.com>
Reply-To: Ivan Babrou <ivan@cloudflare.com>
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

On Wed, Feb 3, 2021 at 7:10 PM Josh Poimboeuf <jpoimboe@redhat.com> wrote:

> This line gives a big clue:
>
>   [160676.608966][    C4] RIP: 0010:0xffffffffc17d814c
>
> That address, without a function name, most likely means that it was
> running in some generated code (mostly likely BPF) when it got
> interrupted.

We do have eBPF/XDP in our environment.

> Right now, the ORC unwinder tries to fall back to frame pointers when it
> encounters generated code:
>
>         orc = orc_find(state->signal ? state->ip : state->ip - 1);
>         if (!orc)
>                 /*
>                  * As a fallback, try to assume this code uses a frame pointer.
>                  * This is useful for generated code, like BPF, which ORC
>                  * doesn't know about.  This is just a guess, so the rest of
>                  * the unwind is no longer considered reliable.
>                  */
>                 orc = &orc_fp_entry;
>                 state->error = true;
>         }
>
> Because the ORC unwinder is guessing from that point onward, it's
> possible for it to read the KASAN stack redzone, if the generated code
> hasn't set up frame pointers.  So the best fix may be for the unwinder
> to just always bypass KASAN when reading the stack.
>
> The unwinder has a mechanism for detecting and warning about
> out-of-bounds, and KASAN is short-circuiting that.
>
> This should hopefully get rid of *all* the KASAN unwinder warnings, both
> crypto and networking.

It definitely worked on my dm-crypt case, and I've tried it without
your previous AVX related patch. I will apply it to our tree and
deploy to the staging KASAN environment to see how it fares with
respect to networking stacks. Feel free to ping me if I don't get back
to you with the results on Monday.

Thanks for looking into this!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABWYdi15x%3D-2qenWSdX_ONSha_Pz7GFJrx8axN6CJS5cWxTTSg%40mail.gmail.com.
