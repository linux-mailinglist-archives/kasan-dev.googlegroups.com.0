Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIEURT2QKGQEPFP4H2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id E53B81B7A71
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 17:47:45 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id et5sf10216736qvb.5
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 08:47:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587743265; cv=pass;
        d=google.com; s=arc-20160816;
        b=IXZhAqnaqtSB7fmmrp153812jFuCdONq1i2IiUeOmeYDNjTCMIBOCCGuVLB6lZXbQ5
         nTQKuIPoS94MusTaFG3OiyKq5yAhDswG5PGbzMqYGqy8fx7OUKtd8TaPPQoNsKhvPQjI
         sEDGx7dCsbnDTJ2nTJUzQfwxD4+vmAsWj+Eqj202wpDPdbC8+g70tmCNo6SNfIIvR+DU
         TpbSxP0A0Xrly1/j8AAMWmNWgF/K9SNya/3JGYTZ5p0tuGsJe4MheHvkW6KbeSsHcTTJ
         cmzf3XuC4mNSBq0lGAM0DClGljh1/mIHe5vrtwwWA4RCE+zJZRxLUG2UADASL7DWReji
         O1NA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=ODqxUZrIba4ePS0EN+LdD0EjcSi2l/YF7IjF7NODoAU=;
        b=z5tbadJ3h7T/B/R9NwLQbcUjQM4ulmPqYoyfYZx2iU35j6m7pJRlIlsKVVabfHQRDO
         VcNWF4cuHGubDbGOUmf25Vjs95liwo8vJ+/IgcUnvU57P8dOnAxveYtTrKH/otVe3r8m
         eeNpO2jKTEiC3WlZVCrZ2PbN975O6uefQZQj0UdaBh0l6sSFh2fYlhRSN/Yme9DfZqXD
         7BBDbVcB8BOYDbEhFCT2JpUZLblOQtkAKKwYPm6kslmpmcl/MiPA3e3iKUlqTbXHiGXc
         GpF+W7yCd+qq9DfT9EY+qlorkK5v7PXfyRe4QBZ10cgSF20/D1bKGJYUmWU/gDVJN2Ku
         BPFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vCckSVmY;
       spf=pass (google.com: domain of 3hwqjxgukcbojq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3HwqjXgUKCbojq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ODqxUZrIba4ePS0EN+LdD0EjcSi2l/YF7IjF7NODoAU=;
        b=UITToWhnR4HJRBLWGF7Pw1K3YKth4tENczzZjr5RmY047ALxvep9UmwyNvg7l38lEs
         Utl6Zrn1SbYhmDeSm5NRvY7SUvO5S5TELzd3vQiQInxijDLO7DTeKLlf6UA5JzKRl+Ih
         e+u8Ig/WjApavbISEtOmBsNgyrzwFxU+lUe/DqxwPeMG1hqlB26sD2Xbt6Eey55X7o+N
         7Stv6k6OHrn/jv45kuvzKU/jZEvbbLfsTHe2dcRW2UeauwRN20NkinLAHl556ZMXBkju
         6V57FlrnkeYedmv2nElGW346OZDj0gXC5ZV1kV/+KjKVgfU85MF77zLFchzHx8W5BEM1
         lXHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ODqxUZrIba4ePS0EN+LdD0EjcSi2l/YF7IjF7NODoAU=;
        b=sVY5hQ2FUD8xHnEPo7pcY3cRCEGorOyGfCHgdegXScJw2locOWQuL1ORTR3C2UpKTW
         KKid3aWC1hDv1W8hEv5FzqsZVq/qD8D0JtArRcGyt5pg62IssVHuyqXoEkxzzJadwInZ
         3Qy39LrdanEQXePuuZI2o9r5kMaZQFQ/MeTP4tXw1SEWva93fNOP0fhnrUAtD4g4HWsk
         ExBvczAFpRm1J+EsD0igs0hpjcJ1VYQUX1ddTQRsQKfun9VGfh75jQkBrSlQLQSupxFC
         rwcHlFOWcIJbjNOdATK1rNrEAYMljCwWa59P3OiiBmyWmfXoTOmHetKmbxtqpjeyzNJS
         Vp9A==
X-Gm-Message-State: AGi0PuZOAgJeXGODYv3BXdSnMAVPuXkBoqb4rWjXeYtzlklW2yOOP9pZ
	UBfLrDsfSU1NtKlXeAM4PxE=
X-Google-Smtp-Source: APiQypIAC8p+m0+CTGGmwXjhyddfstQrp+MiTNzKzstmNbcd9ORalZGQIL5BKR3KBiDrskdLDYD3Pw==
X-Received: by 2002:a0c:e204:: with SMTP id q4mr9833690qvl.16.1587743264813;
        Fri, 24 Apr 2020 08:47:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:8d49:: with SMTP id s9ls3127486qvb.10.gmail; Fri, 24 Apr
 2020 08:47:44 -0700 (PDT)
X-Received: by 2002:ad4:5a48:: with SMTP id ej8mr10186008qvb.122.1587743264318;
        Fri, 24 Apr 2020 08:47:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587743264; cv=none;
        d=google.com; s=arc-20160816;
        b=xyhCz53pHUD/JzZ3MMEamh3XNqPOYT88Is8cxZY645hcgcozh7yTzg2WHoWBibn2Mi
         qjRx2fjQhENjHSy2Jz0qaa28jbMAUTzakg8zoP4IjAHBBA+RxZcRXPHCR2+VdBwlqURq
         LXNYgJxDYLGMA5CyCr9j7oPJjBbo4GMvs2ThHeL2RpYqbKOo9/D8k5DpsjrdAZ7i2thN
         i8D8rXJx+Nr2JKQoSDT7miITGOux3lT8RvsdLikAQ0BvlK1aISL8Q3FChGilsWULXInB
         Em7vIdCDKiTc5n4TLlJOK90WfrxikhC5MSTrhKcaPrSfZ4J985KLc/2YmJgI2nyBCOfT
         oDTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=oVv3oHwxIfr4RsJUouPNW2RXip7ts7Rm/qpNl5CFftM=;
        b=Um+Yxt7fAjA4UHRFHfEqf7WkcURz0yW4toJZ30ukzEB1HJaE3a6wb+4acV/gziBXHY
         uECLyKHNzRO7vSze4wgAoWXNj7M/v7mpeUoILmNvLMmoR1xZ1x19E4tO6uZJ0tuOL+pN
         hkRspApUpe1O9WOdPNBLdFxXu9NWN6mGicgIBkR1gJYeS2l/BE+6UKyWhJZUQMnDuHdG
         RWYuFb28uRrXBpEUHeWB4ZB0JXRwk3iKH29/8jgZt8vC/nbC8r77M56Hkd/U6xQi49Uz
         6JDeKOvBz8JRVyrtoY5kEjYtI9+8cbz7Cn2mE/bsVx+hBTowG3joXhhzMe/YvO1HQtoN
         m9Sw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vCckSVmY;
       spf=pass (google.com: domain of 3hwqjxgukcbojq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3HwqjXgUKCbojq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id h33si420248qtd.2.2020.04.24.08.47.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Apr 2020 08:47:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3hwqjxgukcbojq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id h185so5567426ybg.6
        for <kasan-dev@googlegroups.com>; Fri, 24 Apr 2020 08:47:44 -0700 (PDT)
X-Received: by 2002:a25:dd81:: with SMTP id u123mr9210131ybg.109.1587743263914;
 Fri, 24 Apr 2020 08:47:43 -0700 (PDT)
Date: Fri, 24 Apr 2020 17:47:30 +0200
In-Reply-To: <20200424154730.190041-1-elver@google.com>
Message-Id: <20200424154730.190041-2-elver@google.com>
Mime-Version: 1.0
References: <20200424154730.190041-1-elver@google.com>
X-Mailer: git-send-email 2.26.2.303.gf8c07b1a785-goog
Subject: [PATCH 2/2] objtool, kcsan: Add kcsan_disable_current() and kcsan_enable_current_nowarn()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, will@kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, jpoimboe@redhat.com, peterz@infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vCckSVmY;       spf=pass
 (google.com: domain of 3hwqjxgukcbojq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3HwqjXgUKCbojq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

Both are safe to be called from uaccess contexts.

Signed-off-by: Marco Elver <elver@google.com>
---
 tools/objtool/check.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index 70e721002743..a22272c819f3 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -482,6 +482,8 @@ static const char *uaccess_safe_builtin[] = {
 	"kcsan_found_watchpoint",
 	"kcsan_setup_watchpoint",
 	"kcsan_check_scoped_accesses",
+	"kcsan_disable_current",
+	"kcsan_enable_current_nowarn",
 	/* KCSAN/TSAN */
 	"__tsan_func_entry",
 	"__tsan_func_exit",
-- 
2.26.2.303.gf8c07b1a785-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200424154730.190041-2-elver%40google.com.
