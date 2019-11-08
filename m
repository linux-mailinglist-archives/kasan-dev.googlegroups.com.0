Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3HUSXXAKGQERZXMHPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id A6C30F4DFF
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Nov 2019 15:23:40 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id o202sf2401482wme.5
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Nov 2019 06:23:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573223020; cv=pass;
        d=google.com; s=arc-20160816;
        b=oxMs8Y8TphAnKermdPlrrf+6/RaQZAvXlbo9HVr7chIPh6qd8vJ797tG7KnkWvqrUt
         TaBBlgrDqM8jcZPjYc0iGI2UlI2F6QrS5ZBv9XC87XmNaXCmQrSB+Utp96MErzsEoAdF
         v4MPmDmEdamOHix1E1mKmj7LlTey3emWEim6oxUUTRhZobHWMRZ/hUwspQzpJ/PiM5qd
         VsVegWCe/a3mMBAQHrgJ+Jtnld9wxyAgk+7xLmzg0jp9YaIwnIvYgJiiO21bZGFdHdRP
         pcJzfFJC9TW00CMMhsWbH3EBAsokMsOrfN6jjRqyukYI9WKgdZY3EnMJ3JacH3Coy9U5
         5yhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=o6SAQ0f+ojgtNLruoJ2pzwNIF09ZkfPv2DctwOHl5nE=;
        b=qyTsS25QPkqiAfTtp8Qg5WiQ8JQpv3vCbav/b3yjjtkLTsXHTu1A2jQVNTRDCsXgyz
         6sTTAFSCCoyFCUyCRP2kS4c08OipAaI7rX+lq5a/qkQptPetVhXiFplEZLl7+jneNhF+
         KNaisIPDOCSkTuoAjj4haEiziRu6XEuF1IGedtoTK67JcvtcnUw6YuBSTush7VMuBpW4
         4W2LcXtRIIM4PBxG2o4lG8oJmDUQeXHuCNGNh409mCBYxDfx4eiNlNM3r3y4s0EQZ+7z
         cndqaZCjwsVMZBVRYCt4OrTsHBsJ2ye5tvlJPZxRBsJQC9KFWbHNS24zFG4eBvFCmvMn
         Sf/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="ory/CuML";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=o6SAQ0f+ojgtNLruoJ2pzwNIF09ZkfPv2DctwOHl5nE=;
        b=An3PRTMc0zGh4ahk9E5ytgHKanZrKs7jZSzRyxV3Lk2XJ1//fcA88dXoluvixEHEsW
         yVMERyXp9jAPVtjCPxJjsaIb0reR/uTzQV3BHso7D0/rGIrfFAkuhCXZP3+d9nh3G0Mr
         bJIvQeGdHMUEabePBbzIPmT3SmczMOYsvQfjxUb7EhRWcBFaCIUVpo5UcLoe5dRWgYOn
         gqeDR/2ellJFe00mjHHehi2omvRxyESXCYSElLDqDdd8q+zpFS2JVzhJKjq7Bu7hLHXu
         0muPJ9LodICOq/QNCFkSAAID7zr6zuWvoX+X/hlsFdHnaSmF/JcIgrOtzcEFE7MBI7fY
         YilA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=o6SAQ0f+ojgtNLruoJ2pzwNIF09ZkfPv2DctwOHl5nE=;
        b=W00Gr8zhdGrHKLaSz5IGShdyJCMOPsC7CcjhpYHCFGdtpiIg4oylw9RDrRmXbGlpgX
         B1HQGjCeLGK+ktqdly8jBQYIshwQO4sEC9oVi/KUV74CW9OJnzAzOHd7Mlumt1JgF9Mp
         sjw25RI/i2NvA3McUr0MV3OIBCwIfmEj9QsxMf5FEG81EpZLoTcGEcTyYPSLiq8gXHkS
         I5Cq2mJmZnIKjIVqXNFWLXqdClmvuXAKayR39kNkf5By9HhIaskZKkta561d3sw8No4G
         sJi/wY+KIDwr+geT9NAIvdrkTIfNGezF+cV8u66o4cbNxUx4ZRkNI0i/QJ9/3fmMdeh+
         NORw==
X-Gm-Message-State: APjAAAXATM0OUliYPTACwd4sdgWcTpZaKcC2JCY9bXOUt5eR/kam4VOe
	jN7jYtZAPAqkP7lwqGIJTKc=
X-Google-Smtp-Source: APXvYqxrvLxyjYRb8VVh2AxzvJjHk0OGl70VIE9byKFc5rKO6IVOLEfb2FqG4dXk0qU9mxkFHFgFQQ==
X-Received: by 2002:a5d:4712:: with SMTP id y18mr678254wrq.328.1573223020274;
        Fri, 08 Nov 2019 06:23:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f10c:: with SMTP id r12ls5990784wro.11.gmail; Fri, 08
 Nov 2019 06:23:39 -0800 (PST)
X-Received: by 2002:a05:6000:11d2:: with SMTP id i18mr9096159wrx.109.1573223019519;
        Fri, 08 Nov 2019 06:23:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573223019; cv=none;
        d=google.com; s=arc-20160816;
        b=ckNSf/5uQl9yEeC5bEivEG9qhlQpxyCPXbRtJYcLplFlhVzOclae6FJrv0y85wuLdR
         DEcQsTvTARIQTC135NGDSsoTo2mRWPpQngslddXLX6vMbG41Jv0JjMHxEJkDGIDcLMT/
         7yw2CGgUbqP3JLe7kh59vqfiV21sJRQF1IWy92qjW7oK1JWxvC2nDLpXXC+EW//Hh2/A
         sUB5ejaBxn/4Ci/HnKkgPQ5hn1i5whW3rqGj9WuEQxpU1GN1GsOFuhjiR3YZJLwuburW
         RJY6bNLKtGIGlvXvl1hc7ycO+dozG3llQCip+px+ZtD0f3R4xk89aeAXsz8KXV9QQzzb
         BxBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=cE0H/lLtUQTdWA4Vcuht2GzWTV6rZlF0FP9RhMPfa+4=;
        b=PPdSYsPkm8+t3kqPD4l8U7S9PyCS/HqOXCKBpjSBlRyD+v/H+Y0IH5LKx8bbzfttbC
         hUmR5tk/ZjLp5edjMRBOwUCmVParl9RRqBtV6PovwOE3yuUPlnuf7YifVWEiWwGqOy+P
         TQGEKPlXk/N/FpUgknxJ8mL6xdMfZituuXW4mZRpckQk/FRs5kIBsJpolI/ZuLEgy3Vw
         N6lqK9ovaRXkzaFr/Xg5ricSWdDXYYjeS/dLhUDNak4axn0CgOH13XudrFLBruyhXsrD
         gtIEM8Vj4/QD/ej0vzbEGyQ372Xtzdfzd3DmxX6vloB3BPP7StCNXCIIEm4SwvL5qeAU
         k9DQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="ory/CuML";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id c12si537353wrn.2.2019.11.08.06.23.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Nov 2019 06:23:39 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id i10so7247620wrs.7
        for <kasan-dev@googlegroups.com>; Fri, 08 Nov 2019 06:23:39 -0800 (PST)
X-Received: by 2002:adf:df09:: with SMTP id y9mr6302486wrl.25.1573223018529;
        Fri, 08 Nov 2019 06:23:38 -0800 (PST)
Received: from google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id d4sm5377200wrw.83.2019.11.08.06.23.36
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 08 Nov 2019 06:23:37 -0800 (PST)
Date: Fri, 8 Nov 2019 15:23:31 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Bhupesh Sharma <bhsharma@redhat.com>
Cc: akiyks@gmail.com, stern@rowland.harvard.edu,
	Alexander Potapenko <glider@google.com>, parri.andrea@gmail.com,
	andreyknvl@google.com, Andy Lutomirski <luto@kernel.org>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	Arnd Bergmann <arnd@arndb.de>, boqun.feng@gmail.com,
	Borislav Petkov <bp@alien8.de>, dja@axtens.net, dlustig@nvidia.com,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Howells <dhowells@redhat.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>,
	j.alglave@ucl.ac.uk, joel@joelfernandes.org,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Poimboeuf <jpoimboe@redhat.com>, luc.maranget@inria.fr,
	Mark Rutland <mark.rutland@arm.com>, npiggin@gmail.com,
	paulmck@kernel.org, Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
	Linux Doc Mailing List <linux-doc@vger.kernel.org>,
	linux-efi@vger.kernel.org, linux-kbuild@vger.kernel.org,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	linux-mm@kvack.org, x86@kernel.org
Subject: Re: [PATCH v3 1/9] kcsan: Add Kernel Concurrency Sanitizer
 infrastructure
Message-ID: <20191108142331.GA201027@google.com>
References: <20191104142745.14722-1-elver@google.com>
 <20191104142745.14722-2-elver@google.com>
 <CACi5LpMt1Jp3zi3dQXe-x=nZ4ikADoD2Sr4-6t4HKaarLs7uxw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACi5LpMt1Jp3zi3dQXe-x=nZ4ikADoD2Sr4-6t4HKaarLs7uxw@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="ory/CuML";       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as
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

Hi Bhupesh,

Thanks for your comments, see answers below.

On Fri, 08 Nov 2019, Bhupesh Sharma wrote:

> Sorry for the late comments, but I am just trying to understand the
> new KCSAN feature (which IMO seems very useful for debugging issues).
> 
> Some comments inline:
> 
> On Mon, Nov 4, 2019 at 7:59 PM Marco Elver <elver@google.com> wrote:
> >
...
> > diff --git a/include/linux/kcsan.h b/include/linux/kcsan.h
> > new file mode 100644
> > index 000000000000..bd8122acae01
> > --- /dev/null
> > +++ b/include/linux/kcsan.h
> > @@ -0,0 +1,115 @@
> > +/* SPDX-License-Identifier: GPL-2.0 */
> > +
> > +#ifndef _LINUX_KCSAN_H
> > +#define _LINUX_KCSAN_H
> > +
> > +#include <linux/types.h>
> > +#include <linux/kcsan-checks.h>
> 
> For the new changes introduced (especially the new header files), can
> we please try to keep the alphabetical order
> for the include'd files.
> 
> The same comment applies for changes below ...

Done for v4.

...
> > +void kcsan_disable_current(void)
> > +{
> > +       ++get_ctx()->disable_count;
> > +}
> > +EXPORT_SYMBOL(kcsan_disable_current);
> > +
> > +void kcsan_enable_current(void)
> > +{
> > +       if (get_ctx()->disable_count-- == 0) {
> > +               kcsan_disable_current(); /* restore to 0 */
> > +               kcsan_disable_current();
> > +               WARN(1, "mismatching %s", __func__);
> 
> I am not sure I understand, why we need to call
> 'kcsan_disable_current()' twice and what the WARN message conveys.
> May-be you can add a comment here, or a more descriptive WARN meesage.

This branch is entered when there is an imbalance between
kcsan_disable_current and kcsan_enable_current calls. When entering the
branch, the decrement transitioned disable_count to -1, which should not
happen. The call to kcsan_disable_current restores it to 0, and the
following kcsan_disable_current actually disables KCSAN for generating
the warning.

> > +               kcsan_enable_current();
> > +       }
> > +}
> > +EXPORT_SYMBOL(kcsan_enable_current);
> > +
> > +void kcsan_nestable_atomic_begin(void)
> > +{
> > +       /*
> > +        * Do *not* check and warn if we are in a flat atomic region: nestable
> > +        * and flat atomic regions are independent from each other.
> > +        * See include/linux/kcsan.h: struct kcsan_ctx comments for more
> > +        * comments.
> > +        */
> > +
> > +       ++get_ctx()->atomic_nest_count;
> > +}
> > +EXPORT_SYMBOL(kcsan_nestable_atomic_begin);
> > +
> > +void kcsan_nestable_atomic_end(void)
> > +{
> > +       if (get_ctx()->atomic_nest_count-- == 0) {
> > +               kcsan_nestable_atomic_begin(); /* restore to 0 */
> > +               kcsan_disable_current();
> > +               WARN(1, "mismatching %s", __func__);
> 
> .. Same as above.

Same situation, except for atomic_nest_count. Here also
atomic_nest_count is -1 which should not happen.

I've added some more comments.

> > +               kcsan_enable_current();
> > +       }
> > +}
> > +EXPORT_SYMBOL(kcsan_nestable_atomic_end);

Best Wishes,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191108142331.GA201027%40google.com.
