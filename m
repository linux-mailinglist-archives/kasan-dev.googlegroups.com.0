Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMWFQ6BAMGQEAFUJ45Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id E086332E333
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Mar 2021 08:50:10 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id r12sf680683wro.15
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Mar 2021 23:50:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614930610; cv=pass;
        d=google.com; s=arc-20160816;
        b=Oh4eEXfJ17M4HHuk/wyMbouDC4+Z6rC5JZRna4Sz4lBAa5+VUhVN9QIhZv8Wa1x1yJ
         xuvCoGDvNUScs3raYcObysIqD01HKQWO1bAGAJTuilrqGig+g4stIWdpZ+4IQcy3fLe0
         koN8YZ5p23HYUZ3qyWnqyDLmvaU8CG1YgFRo3Yc3MeM48bGq2Ed97+0F+coNV+DXD/Pm
         roJJ4fMIQR1M/9FMmbTsfaxxJlTBTr4adtXM9VFaBrr2EwExAFj7frPekke8ssxvQoeM
         Lfu//QbEqx+FRGD8HlT/WT1cjfb9n+SyLiupDYAh5dR1qK74jWzoHHD8+OKVVZG1Nk/9
         c3og==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=MJyLI+GmYuWBkIaAPgSZbRYZEHBvMltOUYqtU480HOY=;
        b=gVVXa8RYsFZxqoMoOyV1LhGi4VVloYGBMH7arEPANuD2YhT8Fb9Md1fEGBEzG8l0zD
         O3jcPJsZTflnLhpDTCj7mzN7LzcJTCf+Z+JWD7k7DxzdMRwqvhjyxhTPKUv8f7OGO/f/
         1jCuOw+H5Sv8J787xKhmd1RoRvov7O/rmlnbojxdkmI6kddT85M7gfw4KsRa+58f85p0
         AfJ8J1AqKsHvr62at7TFUnLx18SUoaXG8p+pxMczczWQIh4Rgkuz5skkEBtZx6J3gJFm
         /OQW/RmU40LHshQ4w2IMIaKYL7JmT4/BD0OLkBjxaAz5SN/ddeQmtZfBaQJW5mLXc5zj
         48yA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UCpKUlDd;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=MJyLI+GmYuWBkIaAPgSZbRYZEHBvMltOUYqtU480HOY=;
        b=ielGHh6a2EWWUtZsmTppV7Tl619NEcXYkJglUwx0IMzZsxw8IDSP9HVVunzK1kkAfS
         DNsFbIG9YEM/qUsnCj/CKLbTqusbg9FxM+GEaMSaYXhQDksry5bRkLKU5T9bc396ulmJ
         t/GjeoxfHOa2NPqZfo4hbnB3c04BNVa8B5QCJsEw4fpUFZ5waFNZ07kyBG681QoPA5lo
         H6664BV8qeYhGWlNz8EB1PrT4HIxV+nUgERKpV2GSkyqcyIqmJBiE2nn+YFvS0/pLSBF
         dtL+KtuqPFUsSSA9cHwRsX/DSFUzFedSo9BYmAMPHs+Qu/zzlTQmnrZ03lpAx4pWr/LK
         4DqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MJyLI+GmYuWBkIaAPgSZbRYZEHBvMltOUYqtU480HOY=;
        b=AtL8yJp5kdF535XBAfLueHISAjVdneeM9cRcBepK1oNjmko6Rc2fpCI1Cp/M6axtZQ
         D4C6pRFwteR5OZSZU+u/eVhYJ0ZIsmvhyNnl+wQOlpSN+lWJEHcrK20K4vmyP/WUOlkd
         yT789BH4rFxVeM+WFbq/yErtq4GnKIkCj1IRQAz66jmJWVznGkZElFyry5M9XIjcBdLp
         NqGYCkD9kAziMjQEeUI5Z37HRSwlRMU1jHiiKgILwnv+8xRgytuUHMktvd+a/jQ7GQHd
         bH8uX8+RohoSWpHhiiSDBMCYXfMLYbGZceezAr8Qf2IYTds5nB+qLyEvolPsFkfmw7yM
         nBCw==
X-Gm-Message-State: AOAM530/TU+heEv54gUNM7tX+VT5ucJCU29Ynf+LZBkQ4f9ZY+T5+Mju
	n+qitPJyyZg3vXHyLOpbHs0=
X-Google-Smtp-Source: ABdhPJxuTxLTJYgNT9lyiz8mwHZKlN6Xcc0pa4Rpm0QYrZb6PoRO0jRIEwONslmxKq9j9y97XXy11g==
X-Received: by 2002:adf:80e7:: with SMTP id 94mr7980956wrl.5.1614930610660;
        Thu, 04 Mar 2021 23:50:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:58f0:: with SMTP id f16ls285703wrd.0.gmail; Thu, 04 Mar
 2021 23:50:09 -0800 (PST)
X-Received: by 2002:adf:f889:: with SMTP id u9mr7774381wrp.180.1614930609755;
        Thu, 04 Mar 2021 23:50:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614930609; cv=none;
        d=google.com; s=arc-20160816;
        b=A9BnEPo5nLP+3vRoVGjd+fZvt89xaHb+j5dR31XkS9kit4DnbgXEqTyFelSti2QczJ
         vK+u2bZsDF7Jyfv/dImNe3Hf57s5+t/JqPfkPaoKz6aIwMvr097RlG0LNt+wv0qS2SJ8
         z5xS4fsbZIBuPqKcve9drbNXjIqaF5FVDq/sseeMUHfKyFx9RD+lbEPfnsTPOg/VxK/z
         o9SSL8Br78doffhtKJMnSnAZSBkPZNsxVqCsrJ7h/y3mynZdJ26bWYlOhUOTBDgmCzDZ
         ozGnxIME5KbzUYJ/ldCT2+KRqMVbDmMjZS4F2+ihIIet7HrdQpeUNS14ODbOXtiKZlb0
         Wrrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=34MO9BuNF7F2D8p7lT8uAN48AKZC5qU22L/kUK0Cseg=;
        b=xQcBZuf+5W66kNgw6WbgF9PHalSishi4W40/fggyf7ftrbFp8Q8GQzJ5nX2EXLirD3
         RA/eqSFqS53lRkMju2Zm+u/P40A/ba0jekS6XNZ+6yYk6dSL2OUfUWd8/vqFZ+hnibuJ
         9DU8Ct+LBtbC83E/PzW2SAlakfr8uSxFJKzZhTiF5wbS9HyJDTvkopVIgzV0ExwMIh8G
         cgpTa++kXW3IQ1l1Wy4Hl5qPSdW/LwAdKKDQZ5JhsLtF9PoXmKbaytswSn5B8l3XRQk8
         QiDS6MdfLCttgasH4OzqxOphBTGpuxAv/LMUitLYmI+2z0GZ/8a6zy3gWwbMtdxZD5hw
         zBwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UCpKUlDd;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32d.google.com (mail-wm1-x32d.google.com. [2a00:1450:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id g137si516263wmg.4.2021.03.04.23.50.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Mar 2021 23:50:09 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32d as permitted sender) client-ip=2a00:1450:4864:20::32d;
Received: by mail-wm1-x32d.google.com with SMTP id m1so582936wml.2
        for <kasan-dev@googlegroups.com>; Thu, 04 Mar 2021 23:50:09 -0800 (PST)
X-Received: by 2002:a1c:195:: with SMTP id 143mr7514538wmb.147.1614930609184;
        Thu, 04 Mar 2021 23:50:09 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:adef:40fb:49ed:5ab6])
        by smtp.gmail.com with ESMTPSA id j26sm3009633wrh.57.2021.03.04.23.50.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Mar 2021 23:50:08 -0800 (PST)
Date: Fri, 5 Mar 2021 08:50:03 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Michael Ellerman <mpe@ellerman.id.au>
Cc: Christophe Leroy <christophe.leroy@csgroup.eu>,
	Alexander Potapenko <glider@google.com>,
	Benjamin Herrenschmidt <benh@kernel.crashing.org>,
	Paul Mackerras <paulus@samba.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	LKML <linux-kernel@vger.kernel.org>, linuxppc-dev@lists.ozlabs.org,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [RFC PATCH v1] powerpc: Enable KFENCE for PPC32
Message-ID: <YEHiq1ALdPn2crvP@elver.google.com>
References: <CANpmjNPGj4C2rr2FbSD+FC-GnWUvJrtdLyX5TYpJE_Um8CGu1Q@mail.gmail.com>
 <08a96c5d-4ae7-03b4-208f-956226dee6bb@csgroup.eu>
 <CANpmjNPYEmLtQEu5G=zJLUzOBaGoqNKwLyipDCxvytdKDKb7mg@mail.gmail.com>
 <ad61cb3a-2b4a-3754-5761-832a1dd0c34e@csgroup.eu>
 <CANpmjNOnVzei7frKcMzMHxaDXh5NvTA-Wpa29C2YC1GUxyKfhQ@mail.gmail.com>
 <f036c53d-7e81-763c-47f4-6024c6c5f058@csgroup.eu>
 <CANpmjNMn_CUrgeSqBgiKx4+J8a+XcxkaLPWoDMUvUEXk8+-jxg@mail.gmail.com>
 <7270e1cc-bb6b-99ee-0043-08a027b8d83a@csgroup.eu>
 <YEDXJ5JNkgvDFehc@elver.google.com>
 <874khqry78.fsf@mpe.ellerman.id.au>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <874khqry78.fsf@mpe.ellerman.id.au>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=UCpKUlDd;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32d as
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

On Fri, Mar 05, 2021 at 04:01PM +1100, Michael Ellerman wrote:
> Marco Elver <elver@google.com> writes:
> > On Thu, Mar 04, 2021 at 12:48PM +0100, Christophe Leroy wrote:
> >> Le 04/03/2021 =C3=A0 12:31, Marco Elver a =C3=A9crit=C2=A0:
> >> > On Thu, 4 Mar 2021 at 12:23, Christophe Leroy
> >> > <christophe.leroy@csgroup.eu> wrote:
> >> > > Le 03/03/2021 =C3=A0 11:56, Marco Elver a =C3=A9crit :
> >> > > >=20
> >> > > > Somewhat tangentially, I also note that e.g. show_regs(regs) (wh=
ich
> >> > > > was printed along the KFENCE report above) didn't include the to=
p
> >> > > > frame in the "Call Trace", so this assumption is definitely not
> >> > > > isolated to KFENCE.
> >> > > >=20
> >> > >=20
> >> > > Now, I have tested PPC64 (with the patch I sent yesterday to modif=
y save_stack_trace_regs()
> >> > > applied), and I get many failures. Any idea ?
> >> > >=20
> >> > > [   17.653751][   T58] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D
> >> > > [   17.654379][   T58] BUG: KFENCE: invalid free in .kfence_guarde=
d_free+0x2e4/0x530
> >> > > [   17.654379][   T58]
> >> > > [   17.654831][   T58] Invalid free of 0xc00000003c9c0000 (in kfen=
ce-#77):
> >> > > [   17.655358][   T58]  .kfence_guarded_free+0x2e4/0x530
> >> > > [   17.655775][   T58]  .__slab_free+0x320/0x5a0
> >> > > [   17.656039][   T58]  .test_double_free+0xe0/0x198
> >> > > [   17.656308][   T58]  .kunit_try_run_case+0x80/0x110
> >> > > [   17.656523][   T58]  .kunit_generic_run_threadfn_adapter+0x38/0=
x50
> >> > > [   17.657161][   T58]  .kthread+0x18c/0x1a0
> >> > > [   17.659148][   T58]  .ret_from_kernel_thread+0x58/0x70
> >> > > [   17.659869][   T58]
> > [...]
> >> >=20
> >> > Looks like something is prepending '.' to function names. We expect
> >> > the function name to appear as-is, e.g. "kfence_guarded_free",
> >> > "test_double_free", etc.
> >> >=20
> >> > Is there something special on ppc64, where the '.' is some conventio=
n?
> >> >=20
> >>=20
> >> I think so, see https://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf=
64abi.html#FUNC-DES
> >>=20
> >> Also see commit https://github.com/linuxppc/linux/commit/02424d896
> >
> > Thanks -- could you try the below patch? You'll need to define
> > ARCH_FUNC_PREFIX accordingly.
> >
> > We think, since there are only very few architectures that add a prefix=
,
> > requiring <asm/kfence.h> to define something like ARCH_FUNC_PREFIX is
> > the simplest option. Let me know if this works for you.
> >
> > There an alternative option, which is to dynamically figure out the
> > prefix, but if this simpler option is fine with you, we'd prefer it.
>=20
> We have rediscovered this problem in basically every tracing / debugging
> feature added in the last 20 years :)
>=20
> I think the simplest solution is the one tools/perf/util/symbol.c uses,
> which is to just skip a leading '.'.
>=20
> Does that work?
>=20
> diff --git a/mm/kfence/report.c b/mm/kfence/report.c
> index ab83d5a59bb1..67b49dc54b38 100644
> --- a/mm/kfence/report.c
> +++ b/mm/kfence/report.c
> @@ -67,6 +67,9 @@ static int get_stack_skipnr(const unsigned long stack_e=
ntries[], int num_entries
>  	for (skipnr =3D 0; skipnr < num_entries; skipnr++) {
>  		int len =3D scnprintf(buf, sizeof(buf), "%ps", (void *)stack_entries[s=
kipnr]);
> =20
> +		if (buf[0] =3D=3D '.')
> +			buf++;
> +

Unfortunately this does not work, since buf is an array. We'd need an
offset, and it should be determined outside the loop. I had a solution
like this, but it turned out quite complex (see below). And since most
architectures do not require this, decided that the safest option is to
use the macro approach with ARCH_FUNC_PREFIX, for which Christophe
already prepared a patch and tested:
https://lore.kernel.org/linux-mm/20210304144000.1148590-1-elver@google.com/
https://lkml.kernel.org/r/afaec81a551ef15345cb7d7563b3fac3d7041c3a.16148684=
45.git.christophe.leroy@csgroup.eu

Since KFENCE requires <asm/kfence.h> anyway, we'd prefer this approach
(vs.  dynamically detecting).

Thanks,
-- Marco

------ >8 ------

diff --git a/mm/kfence/report.c b/mm/kfence/report.c
index 519f037720f5..b0590199b039 100644
--- a/mm/kfence/report.c
+++ b/mm/kfence/report.c
@@ -43,8 +43,8 @@ static void seq_con_printf(struct seq_file *seq, const ch=
ar *fmt, ...)
 static int get_stack_skipnr(const unsigned long stack_entries[], int num_e=
ntries,
 			    const enum kfence_error_type *type)
 {
+	int skipnr, fallback =3D 0, fprefix_chars =3D 0;
 	char buf[64];
-	int skipnr, fallback =3D 0;
=20
 	if (type) {
 		/* Depending on error type, find different stack entries. */
@@ -64,11 +64,24 @@ static int get_stack_skipnr(const unsigned long stack_e=
ntries[], int num_entries
 		}
 	}
=20
+	if (scnprintf(buf, sizeof(buf), "%ps", (void *)kfree)) {
+		/*
+		 * Some architectures (e.g. ppc64) add a constant prefix to
+		 * function names. Determine if such a prefix exists.
+		 */
+		const char *str =3D strstr(buf, "kfree");
+
+		if (str)
+			fprefix_chars =3D str - buf;
+	}
+
 	for (skipnr =3D 0; skipnr < num_entries; skipnr++) {
-		int len =3D scnprintf(buf, sizeof(buf), "%ps", (void *)stack_entries[ski=
pnr]);
+		int len =3D scnprintf(buf, sizeof(buf), "%ps", (void *)stack_entries[ski=
pnr]) -
+			  fprefix_chars;
=20
-		if (str_has_prefix(buf, "kfence_") || str_has_prefix(buf, "__kfence_") |=
|
-		    !strncmp(buf, "__slab_free", len)) {
+		if (str_has_prefix(buf + fprefix_chars, "kfence_") ||
+		    str_has_prefix(buf + fprefix_chars, "__kfence_") ||
+		    !strncmp(buf + fprefix_chars, "__slab_free", len)) {
 			/*
 			 * In case of tail calls from any of the below
 			 * to any of the above.
@@ -77,10 +90,10 @@ static int get_stack_skipnr(const unsigned long stack_e=
ntries[], int num_entries
 		}
=20
 		/* Also the *_bulk() variants by only checking prefixes. */
-		if (str_has_prefix(buf, "kfree") ||
-		    str_has_prefix(buf, "kmem_cache_free") ||
-		    str_has_prefix(buf, "__kmalloc") ||
-		    str_has_prefix(buf, "kmem_cache_alloc"))
+		if (str_has_prefix(buf + fprefix_chars, "kfree") ||
+		    str_has_prefix(buf + fprefix_chars, "kmem_cache_free") ||
+		    str_has_prefix(buf + fprefix_chars, "__kmalloc") ||
+		    str_has_prefix(buf + fprefix_chars, "kmem_cache_alloc"))
 			goto found;
 	}
 	if (fallback < num_entries)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/YEHiq1ALdPn2crvP%40elver.google.com.
