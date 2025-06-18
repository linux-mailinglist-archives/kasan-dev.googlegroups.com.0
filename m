Return-Path: <kasan-dev+bncBCCMH5WKTMGRBGMYZPBAMGQEGDDFG2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 9BCA3ADEF20
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Jun 2025 16:24:27 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-3ddd5311fd3sf70881445ab.3
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Jun 2025 07:24:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750256666; cv=pass;
        d=google.com; s=arc-20240605;
        b=R8JvREcS46M6Ny+VZFvqqxAyVnlvjzefbYcXJNuaILOdBtNWmvhiCIqbiuoUeSgPBe
         2jfNqiQ60VBqTnIy7VsB6nPXEZYOGleACD+yC1vcU6lSCrYU1gxY6IvHhYb8xmOfZlH6
         JUm8FKZqcNOoSaP93GiilmU9oTd+N4BPumT2nJHSoO8zCFYzSnbioBaw/GAgPZtP+dRi
         qvOr8SMTKVxk7Ga+tzPBTP9gWql1lpEyGV5P+8d3qXdKiAZ8hxyQ4BruJSbDOBSHe06z
         mp3l4D2O7CNUJ0Z8Kxqn379JFj5WyaLKIdQP2fBe+jUa4Uu5FpDN9Z3nxbvIfNZ1xHfv
         LHIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=13aKPpJ9i1NL4XfLfIPMgXl43XLKNZyTN3cg+hNCEXs=;
        fh=otK0hln1d4tg1pdcQn4lUZpYw3fy9uOsy+9znnoNqQI=;
        b=HyLOal4pvKxHzbR9EaMUEYWSGe6L1FNgFor1jYi0C9Vy0qfZcGdwnDnRT17zwb7uNE
         7K7aRdziHalsdfUUSIXs9h3EwXu1RiKFRwUtwFMA20Et4nzNX9opc7YpKVGMhAAtNwFR
         ptUXA8tTT4bwIjYy19dr5GcDnP0AwL+S8S7qv3l+BtTkh/1MEcLHisP6RDtWt8aXLdgz
         oKd987XvfY/sG/VhUsxH5K+X9q8BwcujiSQyJiAJ88hALnJqpCasllERNFAN0JAqULUv
         eqhydL2/r8+gmfVCnSGBQufb9B+5+ZUEVTLOSiElPYn9dp7U81u5ksKBFSEZIE2MEyMC
         2qNQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="k/cHSYxx";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750256666; x=1750861466; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=13aKPpJ9i1NL4XfLfIPMgXl43XLKNZyTN3cg+hNCEXs=;
        b=eCgkPJy8XTmqkfFVUmM2KJnTZ92okEnOUQX9bthQU/yEO3diyxPzCUnZ63kl27HftV
         MEJFkwMQXhlmTeTJFaPbWJUafUxL4HqIHciJLM6xMqoIlNCCzFe5mQpINY++yT4x4Q7q
         j3+Ftg83J/vP92KXIC0aoAUeYqEXvwrdlbzZPicFETzayrlVU8V3jfl3qWNFD/BLmL0P
         LtmduRyplZZLNXM2aISrfEPX46fk0B4qQVnuW1z/J3K5iIIZ1mmMQ6WJ7noBCEiZsMrh
         auTfKSwT+DiRfJH2DKjq9ZJFedoRQUul4lN3iIfJbnOF+hg9DCMiGL1eNyIYHkhr7URC
         eTcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750256666; x=1750861466;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=13aKPpJ9i1NL4XfLfIPMgXl43XLKNZyTN3cg+hNCEXs=;
        b=c+v6/ecUt1ZrQk6AS+Pfx7HXLErtjapi2wK/QdZtQm5poApQ9HYYBWPBQTjRD749bp
         xqXAfflkTCoijAQz8a/k197lWdvcjwQ4tlX1Fxr2LRQEUpP6ku6LZfa79yj5mfgaAMnr
         R3DW297HwPtRtYQDDlvFMO3Omsj3c1pSd2agDzWVZB/cHIhfO8rpIG0ochzMor+wIxp/
         v+9F9WrAA49G4f/UQ6gytI2C5IbKnzNdvyBGX09a9XW5czESaUonBLvO1XB9fZBADcnh
         6c+qxbddvMFAjzDQtyBWs2fg4As3PLDhUDM4nOh9S1MHHne8KsfQVYlPSYDCviuTG7Vw
         nzBA==
X-Forwarded-Encrypted: i=2; AJvYcCWJtxEvw9WAD8I4MX84HQ6ekG8tBI3A6Ej9kqBbKUxiRya0Oc1ZdTiAsl3ew5n4vlC9f54C3Q==@lfdr.de
X-Gm-Message-State: AOJu0YyTA9m2tX3ENb++J4nBfFxnT72H7jpe2JVG7ADby0kxfe3KQf2U
	OaXOqlvexC1hMi3SdQWLuAxN5Ou4er/LR2/tJrc6EWiBq1+LWq9uNMIV
X-Google-Smtp-Source: AGHT+IHO3uw/8XDzghoAnH7UmHYIXlJf+Vqvsm2A+fPceVoUlCAm3ooHIBM/BcH13ZsG+5M3Tv80iw==
X-Received: by 2002:a05:6e02:4509:10b0:3de:287b:c430 with SMTP id e9e14a558f8ab-3de287bc75dmr43278905ab.3.1750256665989;
        Wed, 18 Jun 2025 07:24:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfgDRRcYIIs6SKuMfaVofwQLvsfAkdoTab7hV/dFP2LWA==
Received: by 2002:a92:c7d2:0:b0:3dd:bf83:da96 with SMTP id e9e14a558f8ab-3ddfb4b7913ls47950805ab.2.-pod-prod-09-us;
 Wed, 18 Jun 2025 07:24:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVNeCxqAlzQLm+hMTqynfIiidlDuEyY5aMLLPPsB1HJOI5IHaXTzOZwCoeTdyG7Q6euyCyU4Dt2V48=@googlegroups.com
X-Received: by 2002:a05:6602:6d12:b0:86d:9ec7:267e with SMTP id ca18e2360f4ac-875ded0e6b5mr2497533039f.4.1750256664093;
        Wed, 18 Jun 2025 07:24:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750256664; cv=none;
        d=google.com; s=arc-20240605;
        b=cXe1K9YFF595nT1Bfyvz1Rdk6lWWM/Dg8kJlXEhMg88QWlQs8EC4NgwJ/q7VskX40K
         MA1BPU+TMesQdsDOGFLhNK6O3CTgG0ihzoTYppRhCGvMpQ+Qt6uXIxT02HzjXFB/1BBO
         INRn7u7nXPFpe/SCMPDhp1ga3oKh82FwajfMmcix6qhUdUtkMC8FceG2uv9hN7yc1xki
         iouQBpJrTSytQKX7fVQV/DzjOMTUOxYMCmRI0L3egv23INE1eE2fultpPxxoKJsv7PXk
         Uvx0c9GnHLO5/9uPAjPBnUA8lNi+qBJWJjethjdQ6UqI4E+qHMj7qOuJiFJzfg6ouSRh
         KC1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yUcfR2kwkjbsjTzvnqaKQjl0q9VATkRLDawL3wYx9EM=;
        fh=rY4Y22PktR2Ie5TtsbiqcW6ljO0a+wlU2kw6jvyIrdk=;
        b=iJxjyY6UbU3KKk7DRGtJX7M8nN+xbpoNde8zkQa/iWpwAAXVpJUmb0iPI1d9BoRSjj
         AU5hQxDdOBfTDWw+1ua2BdMeybntyULKCbQAGmoL7GS4uhgIbG0hMV0kgLZ7Ubj/mqVf
         +sNxYM3ClfdqsyTT35fS9NeRtrcno+TylKlnprc2Ny5N9STQKKulHJ8ukx5PH5Lr5rVs
         DzSX4ndCBD802xF16d4rC8hXNYE7/D2LGvxFzVxlAg3gJKYA3sbfsaAg/iHy6bsUx8Kf
         iy9ITHcRNB21kIsSHMx+gyr6VPMZdR8XGK7OKr/zdDE43+JNNbTy4NuGoYp+LO4627DK
         zwVQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="k/cHSYxx";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2d.google.com (mail-qv1-xf2d.google.com. [2607:f8b0:4864:20::f2d])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-875d580927csi51849639f.3.2025.06.18.07.24.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Jun 2025 07:24:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) client-ip=2607:f8b0:4864:20::f2d;
Received: by mail-qv1-xf2d.google.com with SMTP id 6a1803df08f44-6faf66905baso97622166d6.2
        for <kasan-dev@googlegroups.com>; Wed, 18 Jun 2025 07:24:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWDNX0l2wtYr+ETlJ0cnu8RcKDQbkJ5F5HuguYbmKpEpqp0Rn0OgbxgOdOCoM42ol/LXkIXph6aZ6o=@googlegroups.com
X-Gm-Gg: ASbGnctQ4ydAYh+C7B5YVKBz9n8p3yWRv0WER29L1NdZ0DHZuhhvWOydLmYTzI+R3mx
	lIWxMKibbkN7982sAxMVy3cM4sGJvFGFmA1zzUeY68rZLdXj9aXQ9BnBekyO0RNM/ZNwVRjHhZn
	rYF1rZ6jFP5OYqnZRp8PPzJDVj+jSklXnGTFAApbHbFORZ5GWT6FPZAPL23bifNsMRsgDlAcp7
X-Received: by 2002:a05:6214:5249:b0:6fa:c55e:86a with SMTP id
 6a1803df08f44-6fb47759665mr312049966d6.28.1750256663221; Wed, 18 Jun 2025
 07:24:23 -0700 (PDT)
MIME-Version: 1.0
References: <20250416085446.480069-1-glider@google.com> <20250416085446.480069-2-glider@google.com>
 <CANpmjNPass_tPdjwguw5N+5HRn81FOJm0axLDMxwbZLrHHH8hg@mail.gmail.com>
In-Reply-To: <CANpmjNPass_tPdjwguw5N+5HRn81FOJm0axLDMxwbZLrHHH8hg@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 18 Jun 2025 16:23:45 +0200
X-Gm-Features: Ac12FXxlhTVNXm_co53abS-moIAJmLryjKY8L53ZBoxurLT46rDjZIdqZcqlZ5g
Message-ID: <CAG_fn=VmddBTURnLESOQHEWYzsiUJCph9mVKS6W84TPqm3DCyw@mail.gmail.com>
Subject: Re: [PATCH 1/7] kcov: apply clang-format to kcov code
To: Marco Elver <elver@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="k/cHSYxx";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

> > +static inline void kcov_remote_start(u64 handle)
> > +{
> > +}
> > +static inline void kcov_remote_stop(void)
> > +{
> > +}
>
> This excessive-new-line style is not an improvement over previously.
> But nothing we can do about I guess...

I think we'd better stick with whatever clang-format gives us.



> > @@ -728,13 +730,15 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
> >                 spin_unlock_irqrestore(&kcov->lock, flags);
> >                 return 0;
> >         case KCOV_REMOTE_ENABLE:
> > -               if (get_user(remote_num_handles, (unsigned __user *)(arg +
> > -                               offsetof(struct kcov_remote_arg, num_handles))))
> > +               if (get_user(remote_num_handles,
> > +                            (unsigned __user *)(arg +
> > +                                                offsetof(struct kcov_remote_arg,
> > +                                                         num_handles))))
>
> Ouch. Maybe move the address calculation before and assign to
> temporary to avoid this mess?
I factored out offsetof(), because the address calculation looked all
the same after formatting.

> >         for_each_possible_cpu(cpu) {
> >                 void *area = vmalloc_node(CONFIG_KCOV_IRQ_AREA_SIZE *
> > -                               sizeof(unsigned long), cpu_to_node(cpu));
> > +                                                 sizeof(unsigned long),
> > +                                         cpu_to_node(cpu));
>
> Ouch.

Someday we'll probably switch clang-format to 100 columns

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVmddBTURnLESOQHEWYzsiUJCph9mVKS6W84TPqm3DCyw%40mail.gmail.com.
