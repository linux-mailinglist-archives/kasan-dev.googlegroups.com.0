Return-Path: <kasan-dev+bncBDW2JDUY5AORBKED4S4AMGQETG5TYUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D9F59ACBCF
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Oct 2024 16:01:14 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id 4fb4d7f45d1cf-5c9452d6321sf4633202a12.3
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Oct 2024 07:01:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729692074; cv=pass;
        d=google.com; s=arc-20240605;
        b=KApqi/pcdSFzA4ygdrH6uAHArrK+g3CBHSz3O1Xs35tEl8XTE2eYDOr4j4G6GKtcS5
         iTaR4b02V5DDq9hSX7EBGCW63hLO26pU0WwQp5MCCZtJ2X0tBVkXvvolf82PkrOsRhgT
         9HoxlomVTKg6V9yNCmqrW1he+BJdlfob5XbUrGqz8+luwGlFNj5V/suCtnqk+xPtUAzW
         EgvHCcPKkV6Z+FQOP2gLRmmUF3XN+yI2Zwc/RCiZgim+qW1Tw65cpACgY6ey3Dht6jOb
         4p9lwck/brCV4jcOc2n27OL+VWupKBl8b2h32ztXizMUYnzOrD3ZuVUP+AK8moOw28Y7
         8/KA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=CRPOs2ulGTgO2XbtnX/rm70qR2gmiraGH32yF3QoCg8=;
        fh=40ADOSznajsO8uOj2AV4YRacf8Xb+dCDDKI80sSlYhk=;
        b=PTfA9IMxlRu5AyW2QsIV5IRU07hhU8UYJlovZee9pyuSkNL1dvBhMt8wWUfh7ErwL4
         +5wjCaVLWn7578KO/maXvuAnaempwJaaGj+ab5qO9863OGl9i5hEGQfoJQ7B04pxTGlp
         kKP9n5xYsdE6y9UVM5HZbq1WmX+dRVTCao87/Fh85mksfs8q1akgm3Rp9w6v2aVPZkyO
         SnS382/zgM9KTmXIP6HBKGzhEuNmC4UL4RSCfsg/nLJVnvyPrFhuJpoazQfOm9TfW2Gi
         DgyRXcfXSBBDiAwoSgWHsfLxcvqvWBVEh5AsKjy9m37yPcmR32O//rkaWCA8Z0QNxi20
         Oojw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="BPYFKg/e";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729692074; x=1730296874; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=CRPOs2ulGTgO2XbtnX/rm70qR2gmiraGH32yF3QoCg8=;
        b=F+2BdeEDVB14mBwnbPAukY2WyAwULkqhcUeHmbvc6PMqmCtiIIhEMvaMjWAwpeo194
         O48Poo/kRMuqT4kX4jut7v8yi7WA7wXJIHJM1nlpDnK6Ap3Bb7SRK0m/1JFSDoas1gws
         WcF68wUfVxmQp+RgHaReCh0Clh+XdIOUCQ2JsHlnyP0qa7bxuuEAbE1rRhTRLyAydr3O
         kwxxkCVDe/r/GJWltObMlVD7HOaRi+Lk9+cc3Uvy2KITdVWVJeI1p9dTecHA7yHU1T91
         kGQ8U2/VzjtUh/l+KkRQvrYmctu9OI9cd3uBs52b+Ryw/yFGUWDFP6MA2hIGoK1lqqrR
         LMvA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729692074; x=1730296874; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CRPOs2ulGTgO2XbtnX/rm70qR2gmiraGH32yF3QoCg8=;
        b=HMV0wAm+w25Gg3LA+wnzksdelT6+HyCzJ4jw+8rN77SyigazoswCUps45pHldC8Mij
         jyyvByAXbFMWh1MBt5ZjIxdQKUDNJFk4weyAACzyF75Z4aYl+S1Xurk7Uf1W8JKCpbCF
         6kbf5fS8Se+Dne/OsIO3AOSepbI+VbxtAe1ImCMnZz52rnHRD7P+CF+Zb5qgcRLh5VI2
         lx6mduzOFh1liCn54aE4wUwWeriaH8e+AgmpyV2/UuK6qKIBKRzeGMIfN3Zu8vkhPa+v
         YJUTToh03gzug4geOAl2mNRAh9Ax7N4LpqxTFk+7LT9xUdjOGqjWlhqm4iAL+39clv3G
         yxFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729692074; x=1730296874;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=CRPOs2ulGTgO2XbtnX/rm70qR2gmiraGH32yF3QoCg8=;
        b=ElYl9AT3Aef5q6Gw3elrDWT9l7mBtoNqqAB5wC2h0bVdHv20x3BjRUcvOwzOlGpOHJ
         U/nk05JxnIvUj6TIffZmGYWWzX55AkKeW+coOeq93F1zyAS0UeXpWt/ev4h0Jg8JhSqF
         E9JOVo56n2p9SedFL+eVjAZ26OGdiYsN/BQwmyg6VZhY5fCug2xzX/iqWGyupfN2LLuV
         x/lMbiv2UXHy5WkrBaz5/MRvDsGQo6Yp0kNfdVDwW7pkTCQatT1JBYTKv9vpCdWWr+g7
         dMRXsLXbvv55uhX/KXzWXCSyzmkgQEEb38GC6MX+tZHDXSfaNw12inMmKPwllnMINzLX
         5TTw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVvLU0DhBCIEs6xqtG6kdwBus38mHRxxnj0c8iNRpy0buRIT96L6ISw6BUWX+tJYBryJrAGEg==@lfdr.de
X-Gm-Message-State: AOJu0YxATwKUb4u9dRGhobuF8Je63dWzue2jzvDDOMbKi1apbVWt9bdu
	iwK1NEvfPpbeoWtcg1RYelaFLhNlUXEr/ulvNkxwNiO0UEHKf7MZ
X-Google-Smtp-Source: AGHT+IFVNyvFjI5CmKcZ5GQE9MIIq72Ld4b8TkXIyE5+IrfLLl3qIGKvao/odwC3h4aoOV2lzwx64w==
X-Received: by 2002:a05:6402:1ed6:b0:5ca:18bc:8358 with SMTP id 4fb4d7f45d1cf-5cb8b264348mr2464537a12.24.1729692072753;
        Wed, 23 Oct 2024 07:01:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:3489:b0:5c4:6c19:f74f with SMTP id
 4fb4d7f45d1cf-5c9a5a31725ls53929a12.2.-pod-prod-04-eu; Wed, 23 Oct 2024
 07:01:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWx5onVGTubCCj1cOWD+0ouwKYyeneWG4aWIqmhPv9V3QverW9Sb1Ivph1iotviQZ53AavovOReXYM=@googlegroups.com
X-Received: by 2002:a17:907:960b:b0:a9a:b823:14ca with SMTP id a640c23a62f3a-a9abf851d36mr307652466b.6.1729692070299;
        Wed, 23 Oct 2024 07:01:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729692070; cv=none;
        d=google.com; s=arc-20240605;
        b=O5+bojezkwxAEl/GLpOlbVE7J0ECr7O2orzc+mw/YA4Ov/2p/yXRHBJ5EdQRE4RE1j
         PXYJ+9jXf+pqTyb/H2m4kCMW4E1/lC9RTNWQuWflXChI0vNKTXBQPwr2FOGrtZzf99QL
         l+xRlnf9UUljn/HeRlL5wq2LVepmGpkmhU+KVXkevRQGjckgsDrcaNkDSFcC4oAnHaCj
         sMNpeka6aX1Yy5l7mQPQlm8QV2EDsUgVebwgbGfDIIlRITyQpeEeTjVCzgXWkQdJMmyH
         8MWqok+hP3C75IbYuQnzSRHpxVP/ybB4eN3naZGnlBPrgR8xhsRbt6f0HkVwPfgH4one
         4Tqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=h8YzErpd4tdnHMTvH6+uCPbK+63tVcUugmxIwcXzQFM=;
        fh=z/ye7NNFGH8Lnx7bIN99NGvSgTkeGai8+oN212OLGao=;
        b=PvTOhPfpgMpB4T1+HhntYo9p7FB2mdFGqwMvuW4W4VxDLnxJmrcZ7FlrDkXrAXoLUS
         T8nGjwwqnXzp2NGz8p0RWILyLzxDHy7p0pki3nofBiG6hWix+S0yE1lB/8+bmNSMRUth
         JNPzNgjl1nJiU8tsdtxUWS6Fl0VwHaFPhcQ2//ruz1H//r1BScLoqFYF8NWv+rZ/1val
         Gvnbt6tf3RuejA9pdBZVJEbijF+/W3NhiQZalanP80ZvtuybgcZzyOO2drZmmIa+4AaG
         K0WJAXu/ZmloO9eJLXeJsM9odvnSe2EHECEztWIcYUEmu6Pk86Ee6k4u9aPuhYIoUyhL
         v8UA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="BPYFKg/e";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32c.google.com (mail-wm1-x32c.google.com. [2a00:1450:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-a9a90fbe7e7si16331066b.0.2024.10.23.07.01.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Oct 2024 07:01:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c as permitted sender) client-ip=2a00:1450:4864:20::32c;
Received: by mail-wm1-x32c.google.com with SMTP id 5b1f17b1804b1-4315abed18aso65425035e9.2
        for <kasan-dev@googlegroups.com>; Wed, 23 Oct 2024 07:01:09 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU1581xmOYxdUyDILFdZP88U4VGRhE8oA0zv5ermpaT12x0wgeQUymy0TRyOa1RjsiwBvdV13LdCVE=@googlegroups.com
X-Received: by 2002:a05:6000:12c6:b0:37c:c80e:d030 with SMTP id
 ffacd0b85a97d-37efcfa5050mr1831358f8f.53.1729692068380; Wed, 23 Oct 2024
 07:01:08 -0700 (PDT)
MIME-Version: 1.0
References: <20241021195714.50473-1-niharchaithanya@gmail.com>
In-Reply-To: <20241021195714.50473-1-niharchaithanya@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 23 Oct 2024 16:00:56 +0200
Message-ID: <CA+fCnZf7sX2-H_jRMcJhiYxYZ=5f5oQ7iO__pQnjEXDLUS+fkg@mail.gmail.com>
Subject: Re: [PATCH v2] kasan:report: filter out kasan related stack entries
To: Nihar Chaithanya <niharchaithanya@gmail.com>, elver@google.com
Cc: ryabinin.a.a@gmail.com, glider@google.com, dvyukov@google.com, 
	skhan@linuxfoundation.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="BPYFKg/e";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Mon, Oct 21, 2024 at 9:58=E2=80=AFPM Nihar Chaithanya
<niharchaithanya@gmail.com> wrote:
>

Let's change the patch name prefix to "kasan: report:" (i.e. add an
extra space between "kasan:" and "report:").

> The reports of KASAN include KASAN related stack frames which are not
> the point of interest in the stack-trace. KCSAN report filters out such
> internal frames providing relevant stack trace. Currently, KASAN reports
> are generated by dump_stack_lvl() which prints the entire stack.
>
> Add functionality to KASAN reports to save the stack entries and filter
> out the kasan related stack frames in place of dump_stack_lvl() and
> stack_depot_print().
>
> Within this new functionality:
>         - A function kasan_dump_stack_lvl() in place of dump_stack_lvl() =
is
>           created which contains functionality for saving, filtering and
>           printing the stack-trace.
>         - A function kasan_stack_depot_print() in place of
>           stack_depot_print() is created which contains functionality for
>           filtering and printing the stack-trace.
>         - The get_stack_skipnr() function is included to get the number o=
f
>           stack entries to be skipped for filtering the stack-trace.
>
> Signed-off-by: Nihar Chaithanya <niharchaithanya@gmail.com>
> Fixes: https://bugzilla.kernel.org/show_bug.cgi?id=3D215756
> ---
> Changes in v2:
>         - Changed the function name from save_stack_lvl_kasan() to
>           kasan_dump_stack_lvl().
>         - Added filtering of stack frames for print_track() with
>           kasan_stack_depot_print().
>         - Removed redundant print_stack_trace(), and instead using
>           stack_trace_print() directly.
>         - Removed sanitize_stack_entries() and replace_stack_entry()
>           functions.
>         - Increased the buffer size in get_stack_skipnr to 128.
>
> Note:
> When using sanitize_stack_entries() the output was innacurate for free an=
d
> alloc tracks, because of the missing ip value in print_track().
> The buffer size in get_stack_skipnr() is increase as it was too small whe=
n
> testing with some KASAN uaf bugs which included free and alloc tracks.
>
>  mm/kasan/report.c | 62 ++++++++++++++++++++++++++++++++++++++++++-----
>  1 file changed, 56 insertions(+), 6 deletions(-)
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index b48c768acc84..e00cf764693c 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -261,6 +261,59 @@ static void print_error_description(struct kasan_rep=
ort_info *info)
>                         info->access_addr, current->comm, task_pid_nr(cur=
rent));
>  }
>
> +/* Helper to skip KASAN-related functions in stack-trace. */
> +static int get_stack_skipnr(const unsigned long stack_entries[], int num=
_entries)
> +{
> +       char buf[128];
> +       int len, skip;
> +
> +       for (skip =3D 0; skip < num_entries; ++skip) {
> +               len =3D scnprintf(buf, sizeof(buf), "%ps", (void *)stack_=
entries[skip]);
> +
> +               /* Never show  kasan_* functions. */
> +               if (strnstr(buf, "kasan_", len) =3D=3D buf)
> +                       continue;

Also check for "__kasan_" prefix: Right now, for the very first KASAN
test, we get this alloc stack trace:

[    1.799579] Allocated by task 63:
[    1.799935]  __kasan_kmalloc+0x8b/0x90
[    1.800353]  kmalloc_oob_right+0x95/0x6c0
[    1.800801]  kunit_try_run_case+0x16e/0x280
[    1.801267]  kunit_generic_run_threadfn_adapter+0x77/0xe0
[    1.801863]  kthread+0x296/0x350
[    1.802224]  ret_from_fork+0x2b/0x70
[    1.802652]  ret_from_fork_asm+0x1a/0x30

The __kasan_kmalloc frame is a part of KASAN internals and we want to
skip that. kmalloc_oob_right is the function where the allocation
happened, and that should be the first stack trace frame.

(I suspect we'll have to adapt more of these from KFENCE, but let's do
that after resolving the other issues.)

> +               /*
> +                * No match for runtime functions -- @skip entries to ski=
p to
> +                * get to first frame of interest.
> +                */
> +               break;
> +       }
> +
> +       return skip;
> +}
> +
> +/*
> + * Use in place of stack_dump_lvl to filter KASAN related functions in
> + * stack_trace.

"Use in place of dump_stack() to filter out KASAN-related frames in
the stack trace."

> + */
> +static void kasan_dump_stack_lvl(void)

No need for the "_lvl" suffix - you removed the lvl argument.

> +{
> +       unsigned long stack_entries[KASAN_STACK_DEPTH] =3D { 0 };
> +       int num_stack_entries =3D stack_trace_save(stack_entries, KASAN_S=
TACK_DEPTH, 1);
> +       int skipnr =3D get_stack_skipnr(stack_entries, num_stack_entries)=
;

For printing the access stack trace, we still want to keep the
ip-based skipping (done via sanitize_stack_entries() in v1) - it's
more precise than pattern-based matching in get_stack_skipnr(). But
for alloc/free stack traces, we can only use get_stack_skipnr().

However, I realized I don't fully get the point of replacing a stack
trace entry when doind the ip-based skipping. Marco, is this something
KCSAN-specific? I see that this is used for reodered_to thing.

> +
> +       dump_stack_print_info(KERN_ERR);
> +       stack_trace_print(stack_entries + skipnr, num_stack_entries - ski=
pnr, 0);
> +       pr_err("\n");
> +}
> +
> +/*
> + * Use in place of stack_depot_print to filter KASAN related functions i=
n
> + * stack_trace.

"Use in place of stack_depot_print() to filter out KASAN-related
frames in the stack trace."

> + */
> +static void kasan_stack_depot_print(depot_stack_handle_t stack)
> +{
> +       unsigned long *entries;
> +       unsigned int nr_entries;
> +
> +       nr_entries =3D stack_depot_fetch(stack, &entries);
> +       int skipnr =3D get_stack_skipnr(entries, nr_entries);
> +
> +       if (nr_entries > 0)
> +               stack_trace_print(entries + skipnr, nr_entries - skipnr, =
0);
> +}
> +
>  static void print_track(struct kasan_track *track, const char *prefix)
>  {
>  #ifdef CONFIG_KASAN_EXTRA_INFO
> @@ -277,7 +330,7 @@ static void print_track(struct kasan_track *track, co=
nst char *prefix)
>         pr_err("%s by task %u:\n", prefix, track->pid);
>  #endif /* CONFIG_KASAN_EXTRA_INFO */
>         if (track->stack)
> -               stack_depot_print(track->stack);
> +               kasan_stack_depot_print(track->stack);
>         else
>                 pr_err("(stack is not available)\n");
>  }
> @@ -374,9 +427,6 @@ static void print_address_description(void *addr, u8 =
tag,
>  {
>         struct page *page =3D addr_to_page(addr);
>
> -       dump_stack_lvl(KERN_ERR);
> -       pr_err("\n");

This new line we want to keep.

> -
>         if (info->cache && info->object) {
>                 describe_object(addr, info);
>                 pr_err("\n");
> @@ -484,11 +534,11 @@ static void print_report(struct kasan_report_info *=
info)
>                 kasan_print_tags(tag, info->first_bad_addr);
>         pr_err("\n");
>
> +       kasan_dump_stack_lvl();
> +
>         if (addr_has_metadata(addr)) {
>                 print_address_description(addr, tag, info);
>                 print_memory_metadata(info->first_bad_addr);
> -       } else {
> -               dump_stack_lvl(KERN_ERR);
>         }
>  }
>
> --
> 2.34.1
>

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZf7sX2-H_jRMcJhiYxYZ%3D5f5oQ7iO__pQnjEXDLUS%2Bfkg%40mail.=
gmail.com.
