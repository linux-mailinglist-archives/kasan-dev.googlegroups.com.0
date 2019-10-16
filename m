Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEM3TXWQKGQEPKBSHKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3e.google.com (mail-yw1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 986D1D982A
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 19:04:18 +0200 (CEST)
Received: by mail-yw1-xc3e.google.com with SMTP id p205sf19316550ywc.14
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 10:04:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571245457; cv=pass;
        d=google.com; s=arc-20160816;
        b=EcqKEiMBfDE7BzfI1aIkdBUt0C0KzRXfw9okv6m8cXfkBmrJyY5ACoX5YQ4O9I0y9h
         WBzsgEb1wkjFYJKAgBdjRDHi8HEau18BaBiAHdUd5wIjWScid7u+5Jia082kZJ6MseGr
         jxxSDttzB5mOdinirQhoztBB6ahnOpCHoMx9G7QiOqlLjlzs9MfIapzEZOptpFOo6pw7
         fxVp3uX4DMHH7+zRkaZqpgbolsDxVyCRF8Mn32Lme/jKuC4y1qITZEUoYQmuXxfG3JZv
         YmgtP1UlaIDKvXGfSJrcFCRMnoZTEMxefZTTrVuSW8HgtXeyXPyrD5lCmlkhBc+hFuvB
         mtLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VXXniBn8zGX3wcn4TJK1qiJpXk72oHf5Rpg9mByKMMQ=;
        b=bh4z1ItToX3e0xeB14DngBemlvNsguxl7rvcm1z55owpftkk7ng5QT7njNFFOotCMV
         MdtqdoU88KrJcE8j10AyjftwJHLzRJO/QVxljcp15HzqOcZCL3RGDIVn4Ybn7jLEFCo2
         JCN7xETBSh0KhVmMPMBdrhLIFnTtZuqlI8o7BbFH1sbcv944SGYD+YitcLWaFkcVm0qF
         JAauZuwdNpWrIRx2a6Ucpk/1Xbzwnaa2iL38DT83cACSf6hn4vudXk5YY3otwBybXHxs
         kxvlgv5vdmSpoMV++Pc01/k1mK1vfMTWM3RiNq0mnShqJ89ugSZ+gxqHOeqVW21NgA8c
         JBdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SnV6duwi;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VXXniBn8zGX3wcn4TJK1qiJpXk72oHf5Rpg9mByKMMQ=;
        b=sxyGgN2NiF6Y/ugnKFZzSbIMY0kpAZllxPqryaKnbjOXcLaFiveGjANLe4qNFbF+8F
         1gzIsickum7poJb51Wq5QGVNk4V3zV9+iy/sjHZpxETO36p3RXucbQTJVEMquW8KfQPW
         g9/h/ZItzh/0ZLKBKXSrd+cPTaQAe/7qgEKWluNtFwmfnarJm6dXlZqUladn8/NvJlnu
         +q5eDc+LqRPHC/cR0jHL1dklk0W+kTAVGTqxIAAPcAr4z+I9NwOIgqfbZ3nrPi2gliqo
         8LJLJAnhlMT60AufrDAgkBx51ygamjiz0dtGOtqts4QhBDrFj6Dv2r5Y1aPSC1clUFrV
         AnYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VXXniBn8zGX3wcn4TJK1qiJpXk72oHf5Rpg9mByKMMQ=;
        b=q4eDANMlx6NGxUBFR96HZ7mNIgQQTGDK/MARbydJIAAPcGJGsa/Dqm1PY9kUKrVc4A
         LrJnM05+lx85sttxNF9aExB/nJOprPGyE5RuCu7Du0e8gHWBGXrIbprsrf6KRJkgDNBn
         5L/u6dtzTGq345S0l3TrlTMHXM8cYPi+DQIt54k4ZbMYB8SaojfHUp8Nl+4L/R2Acxsk
         1SOCOXwvVyDfAwW3Cs0iaTuJGqNsiWa2BmOe/dgj51z0tZmYXDsWXt0kcV2DugL+ht67
         yXvdfAdp59OqNe/KcTBjt5EYblb5qw52AS/RhL13G+2MCBJb75QYn6Dd+cGY81ETkdGp
         4lIQ==
X-Gm-Message-State: APjAAAU7XudADu/PTXm5TBfATdmrLPpeHOC7bBrEbiKltCpJx5RFnH/Y
	UycD4xQ/IhJ8C75yZfyrqKE=
X-Google-Smtp-Source: APXvYqzOzk0x4AUpJ1vtJnENzq1nOhaYUm/N9vMpe1aaq3A/Uwwds+FQUYRTBLLVCaSPr7jj6b5VNg==
X-Received: by 2002:a0d:e347:: with SMTP id m68mr21857483ywe.183.1571245457599;
        Wed, 16 Oct 2019 10:04:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:3a06:: with SMTP id h6ls2814748yba.6.gmail; Wed, 16 Oct
 2019 10:04:17 -0700 (PDT)
X-Received: by 2002:a25:60c5:: with SMTP id u188mr408551ybb.497.1571245457001;
        Wed, 16 Oct 2019 10:04:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571245456; cv=none;
        d=google.com; s=arc-20160816;
        b=kkZfCh8/pIitu2DuobO5YaHKSxvTbVtVPVcWahvYZNcCvISqRZ3NEWaSLfBBFcXQuY
         Q0KZzEFvwQCQ90mDbm4WhrwjA6k74hrtE7OTkrIWTnJiGizfVzO4MJa67Nw+oq72Cn9G
         erLv6chN3vPBQBiyPQznK8WMbRL11StxccnvG2lDExp6xa0SLPLl6Z1HjeQ/AeXtL+eK
         IeUsInPTksJBnUsbQSzIjmy9kiSMuQYktTlKyYNi4iIuKQZ3xVmAecfDc1CJ140F+TVh
         HCaW4eccINEzbvmCLMB5n/KV5EfYkHymzBZYu+gFSIzlM8Mjn1CKmJ3QHX1zNAn1eyji
         dv3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BSGWH28HRKXwBsAljxNnBMneVoGGH/xuNYpExPGbSaY=;
        b=ZeblYSaJwfUfD6zXAULEEfVV0F2MaHE+SMolD9bFyOAZ5D7ubKyokkcdCHl35F0/hm
         MEmKAX3YnQCkePEOvuTuOF9XzRqsi2aQvT7NYVRASnl4hoIOpi02sMWvx4nSp2p6ExIx
         tk1dDhdfVafrJxdP8HEE1Y6Fxfuzuinr6zEiDhZYsr5b2kV/vj6yQHPlErSaTEkBOdaj
         OBt3kGf434SKprdivpic55hNNLOkYTlOjEGY9q6kQ4O2ITOWpm+DXKbCV4Z84tI0Gi0G
         nrz4PC2CTfXKnStUvLaL2LdC2oaSLpU272K8UmsEjSlvRbvg2idWrsPV933yZvgC9SE9
         R13Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SnV6duwi;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id a1si1790787ywh.3.2019.10.16.10.04.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2019 10:04:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id m16so20680648oic.5
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2019 10:04:16 -0700 (PDT)
X-Received: by 2002:aca:5015:: with SMTP id e21mr4471718oib.121.1571245456250;
 Wed, 16 Oct 2019 10:04:16 -0700 (PDT)
MIME-Version: 1.0
References: <20191016083959.186860-1-elver@google.com> <20191016083959.186860-9-elver@google.com>
 <ce0d1658-c000-be20-c997-34ca488e4406@intel.com>
In-Reply-To: <ce0d1658-c000-be20-c997-34ca488e4406@intel.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 16 Oct 2019 19:04:05 +0200
Message-ID: <CANpmjNOjJsqEtS5jrZ66f3RQSEASjG-N9oMQ377KhmoWJycxXA@mail.gmail.com>
Subject: Re: [PATCH 8/8] x86, kcsan: Enable KCSAN for x86
To: Dave Hansen <dave.hansen@intel.com>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	Alexander Potapenko <glider@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, Arnd Bergmann <arnd@arndb.de>, 
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>, 
	Daniel Lustig <dlustig@nvidia.com>, dave.hansen@linux.intel.com, 
	David Howells <dhowells@redhat.com>, Dmitry Vyukov <dvyukov@google.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>, Jade Alglave <j.alglave@ucl.ac.uk>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Luc Maranget <luc.maranget@inria.fr>, 
	Mark Rutland <mark.rutland@arm.com>, Nicholas Piggin <npiggin@gmail.com>, 
	"Paul E. McKenney" <paulmck@linux.ibm.com>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-efi@vger.kernel.org, 
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SnV6duwi;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
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

On Wed, 16 Oct 2019 at 18:14, Dave Hansen <dave.hansen@intel.com> wrote:
>
> On 10/16/19 1:39 AM, Marco Elver wrote:
> > This patch enables KCSAN for x86, with updates to build rules to not use
> > KCSAN for several incompatible compilation units.
>
> First of all KCSAN looks really interesting!
>
> For the x86 code, though, I'd really appreciate some specific notes on
> why individual compilation units are incompatible.  There might be some
> that were missed, and we have to figure out what we do for any future
> work.  Knowing the logic used on these would be really helpful in the
> future.

Thanks!  I will add comments where I can for v2. For most of them, I
followed the examples of KASAN and co, and will try to reevaluate each
one.

-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOjJsqEtS5jrZ66f3RQSEASjG-N9oMQ377KhmoWJycxXA%40mail.gmail.com.
