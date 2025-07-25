Return-Path: <kasan-dev+bncBCCMH5WKTMGRB5GARXCAMGQEUNKQGNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 655CCB11CC0
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Jul 2025 12:46:15 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-23494a515e3sf16307905ad.2
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Jul 2025 03:46:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753440373; cv=pass;
        d=google.com; s=arc-20240605;
        b=PG8ebcp4ODNvhapJbXpD0HOu6eIYmtOJ8rPZHklFp/sBkr1UXe0u4omyXfkppJSZZF
         p1XzFvyKutsqB+VE9k61KrXU7BqA+ae4A5Mg+JbPDI7lnJHPZWboDcUlhUmzHKv7sPsr
         abGDebILjmIfs6jeFIOzTAHCRBFhBaDLVHPQzsVcS081SFnGe6WTfTfSEf1cRTYm0tDG
         MSAIXHq4MPXisrk24SV4Rf0Udk5tS8HwoJOlWS4GfJqEwagjvuT95FL5aAfU83GoAKWA
         h8Yu5zjVOK51aEQYFMck8eiJVRpboNxsKRdkou0ja6YZYaKtD9h566xolgKxCagrmbEi
         fQCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=raHY/FseNVQ89Zlo9nj10vPLp4GC9QTAwoOp1zU+N2k=;
        fh=MOH3NdP0eonYsrGIhH+pjle63zhU68uT+Nz04mdyJnA=;
        b=gKsMUrKadVSaWSDw21XgFgeRsmp51KxEYMpIZ4I+ybD2WZNO10XPlAm8hmFw56XhWk
         t/JWDlNlyT2ocpyT2ly9QdxxsasUr406oAJrItGoDzHXZuC56Fv21kXYclZDwKnlJP8c
         9T/3w13N2iO3vV+jBLRWOQV4ETWnTjuL3riO4G3KZhzaU8HzPtE03CvWdg+KPKtEdAYr
         mmRdVxTQFM93qs9tr3GqRTz9oD3E2Ogc5ce7yn1JQEfEMOcCwFXPaD+89pb2ZECYuePc
         0vm5NFXuL/+IW+hLEqDIgPVHRN+H1cH0hoekDVkWWOgec5QlkZLh162UxKYBUAybOpER
         5vQQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KVIL6OZL;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753440373; x=1754045173; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=raHY/FseNVQ89Zlo9nj10vPLp4GC9QTAwoOp1zU+N2k=;
        b=wjgHdegGDeYrpzldG1NXG+m/0UnQo9eFeiMG5B1snhcvUHDWw328faU8/I/pU/QiDw
         oTHIVQ5QfkrM64TFiG58eHItYzVM8wflzm58dGa4jXxfy55t57ApQ8CZ+xTpDXzJnzTE
         4v1Jb6djVeQXwFcXZlN8QnNdO3OVgeWE8HWtOvTEeiqOvc9r7LveIKMXoeZ73paFT+eN
         9DBtq/C6U6IyqSk98j1vz1MA/+/TJJg3hv9/yEyfDdCgDkkat8bBnIBKHRJOBhXDUn8s
         PuClWH1dK+MjwTQqMw9yFb0RTOcY8JRkKkXbupvqcczJKkcYhqvv20NcsF2G4ITcYQJ3
         s6nw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753440373; x=1754045173;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=raHY/FseNVQ89Zlo9nj10vPLp4GC9QTAwoOp1zU+N2k=;
        b=gdrV8cQyd0agNf8kG+fuUGbc9XwATbNwr78fZhIKHCaVG5KZxMnkyFcg0iX/wxLWyx
         m2MLgfxKkSawuFuuDNG2GZPuiqmYTOW4kjW+zTSBivGxQtpm8zrh9bWouLDkia0p8464
         LRYOPc3v5hEArSAJ9iSmxHp7vD73Dc/DhPaajPEfBriKlxQWZxHBeSZP1HSs52iDEWII
         q/oAYoaqnmphfQPm3cnDDZiF8i/sgUKoxeMiQVd4P41iSCrGQiUw38nbnEOXf5ypMbCi
         F56RoFw+1g001Zq9b7Z9rmMbeScEfV9ELp0r1YKbaAKShIFPv1lTwX5+2VSSOjoJ2oJe
         OQDw==
X-Forwarded-Encrypted: i=2; AJvYcCXGkLqSKDU7/pkvYAr9Zhzy0+IqcVnjzKYfy5hZdnMUt6erAws4Z/GqDle3fuBNP9kVujijiQ==@lfdr.de
X-Gm-Message-State: AOJu0Yzmv29i93sVPR++sVQNZZmxHzd54bbTkqAyksnp97vZ2U+IPj1Y
	AXmC/rNlF5o3brxeCtf3dOl5gOFM1JBiyYPjGltWuGBRTSuCxbb0fadV
X-Google-Smtp-Source: AGHT+IEWAk7V4K5y6wVTR2JE7DgIasX0uu2kha6espGcp9XgvBO8OfcU3x/66N3iA25jC06thR4VDg==
X-Received: by 2002:a17:903:1ae5:b0:236:7333:f183 with SMTP id d9443c01a7336-23fb3084edbmr20114545ad.19.1753440373161;
        Fri, 25 Jul 2025 03:46:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdueLehHkKn74HRIOrn3HefZB5iNAjHd11dOBRkPGjN8w==
Received: by 2002:a17:903:3c65:b0:238:cdf:5037 with SMTP id
 d9443c01a7336-23fa1b177b7ls19228965ad.0.-pod-prod-01-us; Fri, 25 Jul 2025
 03:46:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXK/VuqvkcP2D1kZjttyS1r3/IcXb0VV/M8L2EfGV8yaRqokpddvns6S5aKa01p0sWvr43sSg86bbg=@googlegroups.com
X-Received: by 2002:a17:902:e94e:b0:231:d0a8:5179 with SMTP id d9443c01a7336-23fb30901e7mr23922555ad.23.1753440370019;
        Fri, 25 Jul 2025 03:46:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753440369; cv=none;
        d=google.com; s=arc-20240605;
        b=MDuo5m5K/glhT30eTmsVYc7EkjGBM3XL0G71iGOwCl8gyoRTJOjDHuB+XO97NeOWJN
         PfUPGwB42BzxMXxctdsrVvdQeXc3Zaa0rfHY3D2uumIKMFW5Kf543Cdp9CbbwLi4Qp47
         EfvLuV085fswxwpRYjXhsZ+ZNelZ1jub4zSwLoi6sZgAfF2qk79QS6veHTnUHkKBajOT
         AebMwQORLchml8wfOQriNxjakz5Dp7x4Ulm5+1JSFkQowbr562OGrROXr8RLqWdj37Pu
         9WY+18Z3VDvnWdX0V+dA2S+jJQRxNDsHjKmrEWUmb61H9ZVEtjfFV2BvxvW+nhDfWrWQ
         1tVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gySqMQaXdvjL1SUF3U6xcl1pKceXBAohIwzO69Rd5i8=;
        fh=yUMkge7GXyPizK0hMHZEPckR50OLo+t41t9AfPKK1xc=;
        b=U9OeaH581FR8Iie2NiZaPG82Tb+uQ4JxgTvIgu8yJGKxFDU4PGH3QLYUPVh/q3xdH7
         8zGi5J2Mimac5UxsD6C6aw/q1s+fNqUuMlOQAydD9BL4XgrcBpTXGLZYkOA4UpRcRfko
         Wg3ceg5x+RFMBpU7be+9aiRIe64Z43jy2DyTFn8tVqdLDtlHNVVHGO+BUbkXbUNzb0Wf
         zX5GudsECaZH8xfpBqae0qEEXnSYZ3VCxzXHt3JVV4bZwj1YrGfhXc92RE62OZXdwksy
         R1fJvKhZ1f1lnEI/72gz5N/lsh5GOPSBlt2w269NMpV2KKYAtUsnrOaiCx8XF7DpPIxT
         5hRw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KVIL6OZL;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf35.google.com (mail-qv1-xf35.google.com. [2607:f8b0:4864:20::f35])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-31e609617ffsi156495a91.0.2025.07.25.03.46.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 25 Jul 2025 03:46:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) client-ip=2607:f8b0:4864:20::f35;
Received: by mail-qv1-xf35.google.com with SMTP id 6a1803df08f44-6f8aa9e6ffdso18713666d6.3
        for <kasan-dev@googlegroups.com>; Fri, 25 Jul 2025 03:46:09 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXzBKTQdZDuCNflMfG3Qe6N1p9nrWChVLCvd5O1TQwTadBnf4y2oz4B777YOPx+oDDP3QGaprO2+Fk=@googlegroups.com
X-Gm-Gg: ASbGncvCZCszpd7c31O9UcVK3Ps/0792Xu8BG4pH91GyrjV5SyEe35B5Z9bKAY3Ts3s
	3RPIMtEAenUx+EeLPxVdeI5uIAtzlkPhI5f50jl7RZzzkpHtGKAUm/CN+GawEEiGpnaU70N08/a
	1Dsfik7DEVRrKmaR6Wf/UeQv/2XHZH5YsUIwZiTux4zsl1hQIP8pjRAVgRqhuEQQEY/HcCepQx6
	xy9griqJRHPvyIA5fu7rG8652cw+VMBY3QDqg==
X-Received: by 2002:a05:6214:767:b0:706:c9df:8f84 with SMTP id
 6a1803df08f44-707204f5ac1mr17171246d6.16.1753440368716; Fri, 25 Jul 2025
 03:46:08 -0700 (PDT)
MIME-Version: 1.0
References: <20250626134158.3385080-1-glider@google.com> <20250626134158.3385080-8-glider@google.com>
 <CACT4Y+Za7vRTQ6M6kKs-+4N4+D6q05OKf422LZCMBBy-k4Cqqw@mail.gmail.com>
In-Reply-To: <CACT4Y+Za7vRTQ6M6kKs-+4N4+D6q05OKf422LZCMBBy-k4Cqqw@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 25 Jul 2025 12:45:31 +0200
X-Gm-Features: Ac12FXwWsA3nZdUcsOE5scpAqUIULEe94j7gJoqbG5voc1b4SXUvntmzYkUXFoY
Message-ID: <CAG_fn=VWX8aRaASWpgkfgFOwJLXOx97ykPHR50MtyBC4E8iJKg@mail.gmail.com>
Subject: Re: [PATCH v2 07/11] kcov: add trace and trace_size to struct kcov_state
To: Dmitry Vyukov <dvyukov@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Ingo Molnar <mingo@redhat.com>, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=KVIL6OZL;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as
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

> > +        * Pointer to user-provided memory used by kcov. This memory may
>
> s/kcov/KCOV/ for consistency
Ack.


> > @@ -382,11 +382,13 @@ static void kcov_start(struct task_struct *t, struct kcov *kcov,
> >
> >  static void kcov_stop(struct task_struct *t)
> >  {
> > +       int saved_sequence = t->kcov_state.sequence;
> > +
> >         WRITE_ONCE(t->kcov_mode, KCOV_MODE_DISABLED);
> >         barrier();
> >         t->kcov = NULL;
> > -       t->kcov_state.size = 0;
> > -       t->kcov_state.area = NULL;
> > +       t->kcov_state = (typeof(t->kcov_state)){ 0 };
>
> In a previous patch you used the following syntax, let's stick to one
> of these forms:
>
> data->saved_state = (struct kcov_state){};

Yeah, I did some research recently and figured out {} is more preferred.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVWX8aRaASWpgkfgFOwJLXOx97ykPHR50MtyBC4E8iJKg%40mail.gmail.com.
