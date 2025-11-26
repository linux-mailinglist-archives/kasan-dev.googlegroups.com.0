Return-Path: <kasan-dev+bncBDTMJ55N44FBBHUWTTEQMGQEETV65LA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 80336C8A3C2
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Nov 2025 15:13:52 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-429cbd8299csf3469687f8f.1
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Nov 2025 06:13:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764166432; cv=pass;
        d=google.com; s=arc-20240605;
        b=HXIxraxzUCn/OdIhjgBew3hxd03w0OUuNfBTRw/JCbJLTAho9iX3p+C38Cy8Cigjmg
         cizvYVIpmQ+lqMBOj9HL6Conj/IztVAj+7SiES8JtuHuRRBMRv+ABZTdmWTOqiSbUbP1
         +yT0FWN/mYZigk5vuXzi/N5V/ckjFda99LcWxcGtgvwD48AjewuJ0jwPDVmITlC13Zlr
         IuIq31rBvMO+o6xAhrpgRQe5/Zp9RZsWNUC+sXzumyh9EbWmWac8PF+4k3FYpjk6aSST
         OQ1b4JZdsGhktBhK/jTZ85LNFh43xFpkH3QhBWBiFSkmmAfyXIzAtfC7ot2Z7z+SFXPp
         OLgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=5uo9X5lmQlbWSCWY3FYCvsMrQJeRlMyeyAk0sYJ25OA=;
        fh=3BUavXDKbJOjhGT/2IIpd+XgAuqOchxudHDPUknSnGo=;
        b=FihrPaz14j70rdu0QpjtOxR+vLd11NJb1N6Hv//c6SJXmn48SOwKQ+JTHeVa/huarJ
         aCGwBhfmV3BmNRV/zY4FqPtHeVUTnYtzMewaLcOQa+sGMf9iirFI74xSLL05P8lrYL0e
         JZpyhk7hX5+VUtnhgp0gn7PaDHLEqsBoUniooMxlrhhFKxideoBEp/wrQ6+Lg/kPIh57
         oRwqqxUSzgwhKgOIpe95DoTQSnN2k05pV22iGPd1T+xT/ea+AFWRdJlw8zXBRof7o6wl
         FvDbbkjcZhSTWJorKRdpQAB4EMs0hmIbj4Bo1T5xl9K+gSbLy2WJxSWo76LS2I++rF4O
         PvlA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@debian.org header.s=smtpauto.stravinsky header.b=DbG2fWv1;
       spf=none (google.com: leitao@debian.org does not designate permitted sender hosts) smtp.mailfrom=leitao@debian.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764166432; x=1764771232; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5uo9X5lmQlbWSCWY3FYCvsMrQJeRlMyeyAk0sYJ25OA=;
        b=fc2jgapdUp/GCbJzUc2jDbVwFpO8fp78zFLIk3iBEhpSgtZDLYzOd0+M0he/EHO46S
         Q0L7oLKdjWEMeh+ACdJOdon8FBc2F80tfb8SVOq/3kObGDHoNNDdpCCf4cvwfAJzH6NJ
         ieDbUEP3O69SujMulT4JvvpqYXV2paLxN+6EXh1bTYJNr3rtHTDufQMp3L8zDNy0f0DP
         C5ShgnxKNvJYJolGaj5OdN9vfHCPgiX4kgJziXfNi/Ma+EmuNf/c130kYOnmYWwi19iU
         5XquRdEC+yBEH7zmpz+T0QfV5dDJhv7HfaPXBAFK+6xVwQz1YSthGfT1f4NGMCKVS/91
         OIqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764166432; x=1764771232;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5uo9X5lmQlbWSCWY3FYCvsMrQJeRlMyeyAk0sYJ25OA=;
        b=kSIJ6Ide0CVdK0Y8xQepJoJ2NWFtvNI0zL8vXRvdttDHN7YVChTolOmNvUxTfLw5yL
         B8r0Y2UufG4kiryokMDxWHxlOV2e8WgQ4b1L6Jcl1dn4SzEL4eQqcUWHEniSSCQal9OW
         yf3KqQ4rTzARoZncVeqa0DZnU+eoJ3v1Gs2IvjNv/GLNi4PBpEMksw4/s8Wy4ryHkUwV
         O2jy9SA47XOGiDrwnZxDD8lj43jPv4Jc9csQ57JfwerR23XzYJVo7LS3MjzhUKi3HI/e
         yUXspFWZf9jLpwEttuQbgvgnBsLLc524XiIHnlfap36p1PDxSOa+5pg6v4THJexPq30T
         he2g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV9CYhY7SEpEZvvTWFLTNe0wB7TMziYM4zKyIRS5iqN4iPMLi08d4ZSojKw0640lXUsSsH+fQ==@lfdr.de
X-Gm-Message-State: AOJu0YxASSppWUQkB2AK0cl8n5Aq6ZKN4pOtxQ4oF0+4+lJiygR3RXqT
	VGWzcii4+0en7lrXMK9sdYrdpubyC00BjiTBVzVGzZqbB74B4cI3u6Z9
X-Google-Smtp-Source: AGHT+IH1fL39FZtFVEgJTijv39RzC1lvzvP2q3CVOZ+B/BGqQpxTY+GGdDWA0iEGPRLokhpzBaiCPA==
X-Received: by 2002:a05:600c:3543:b0:477:1ae1:fa5d with SMTP id 5b1f17b1804b1-477c1142268mr160098785e9.20.1764166431491;
        Wed, 26 Nov 2025 06:13:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aQaOb+8e8xreTcJ96+NxDBR8YMPfTkKCNbvDruJhffrg=="
Received: by 2002:a05:600c:3511:b0:477:a293:e143 with SMTP id
 5b1f17b1804b1-477b8f2b088ls39861845e9.1.-pod-prod-06-eu; Wed, 26 Nov 2025
 06:13:48 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXoF8m33A05A4z3Lm6wHTRk2ZZfpwlo+ibtePgqLfYtq9lNLw38QzrYPcAVtw8DPCGmIOTALylAzUc=@googlegroups.com
X-Received: by 2002:a05:600c:4ed2:b0:477:9e10:3e63 with SMTP id 5b1f17b1804b1-477c1164cebmr187061655e9.35.1764166428473;
        Wed, 26 Nov 2025 06:13:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764166428; cv=none;
        d=google.com; s=arc-20240605;
        b=KhBUHxEFETm8o9w44Tsk+iawm3720djPI0c54VeyYPdpgW/e9Dvdgywgll8OS7UaOt
         bhaVbmf/F0ZfrwH82E2T3/Ha5nwMwZIcup+R3C6SgxOoRlJ4lC5Hw7FRBohNAOpfIeWP
         6I1YiUJaQAcejVtWWkKiDgZnlUikAMEjOQxLY4WGJC0bYFzLrWt2yfr9+zgCKKz9XzIs
         sKODWfRM5jge2AHZ6fNRkN3QM7OOomBUtxknU8UBrTuZi67fg6F4Jq8yWi49sG95NX9J
         Lymqlvq7SuhxM92o+6PiB/fDXFWI7lSsDA+GTzMaJSl/MeYSR/I3F0UUvJjmEwPoqFGf
         FDgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=A7ja4D+EFSRvEgxPFCwdw7yOWGbR0ylzkLPujJe4pDg=;
        fh=VEZXUtxt5RMeb/J4f8w7Ga1Zr+m88T8/xvjdNczV6GE=;
        b=Qkv9EwoFenBsOGF1Fs4aHXdPf/VXDXjI6PJfZV7a71Fao1zXAQtnp4DoIO5zM66+HH
         Mbh/9kCtyktaM2JLkMz1U46Bv/FauaKZrLVKfk331JDJNpZO9Kz03NJQiPB8t7sm4QMa
         duvg2DsHMr43gBPr9LvGUKaZo8nVigeyuxiG3/mIrUA5KhRhezsstaeo56L/mAVkSoyN
         G1LXPHk72u/2uVhY6h+zEl31tdZ1/zMKPY7UkjnWw51GFFe1znNR8zJs3Ed7f8BTImNK
         MihVRJqhXZyZGFIgYV0ajAaHss7OQFKOhxyyErJcwYEkBLX1Vq2WslmawZYbZOaWZzBR
         7h8g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@debian.org header.s=smtpauto.stravinsky header.b=DbG2fWv1;
       spf=none (google.com: leitao@debian.org does not designate permitted sender hosts) smtp.mailfrom=leitao@debian.org
Received: from stravinsky.debian.org (stravinsky.debian.org. [2001:41b8:202:deb::311:108])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4790ab850e2si282265e9.0.2025.11.26.06.13.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 26 Nov 2025 06:13:48 -0800 (PST)
Received-SPF: none (google.com: leitao@debian.org does not designate permitted sender hosts) client-ip=2001:41b8:202:deb::311:108;
Received: from authenticated user
	by stravinsky.debian.org with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.94.2)
	(envelope-from <leitao@debian.org>)
	id 1vOGGq-004GQD-Kg; Wed, 26 Nov 2025 14:13:24 +0000
Date: Wed, 26 Nov 2025 06:13:19 -0800
From: Breno Leitao <leitao@debian.org>
To: glider@google.com, elver@google.com, dvyukov@google.com
Cc: usamaarif642@gmail.com, leo.yan@arm.com, 
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org, kernel-team@meta.com, 
	rmikey@meta.com, john.ogness@linutronix.de, pmladek@suse.com, 
	linux@armlinux.org.uk, paulmck@kernel.org, kasan-dev@googlegroups.com
Subject: Re: CSD lockup during kexec due to unbounded busy-wait in
 pl011_console_write_atomic (arm64)
Message-ID: <k4awh5dgzdd3dp3wmyl3z3a7w6nhoo6pszgeflbnbtdyxz47yd@ir5cgbvypdct>
References: <sqwajvt7utnt463tzxgwu2yctyn5m6bjwrslsnupfexeml6hkd@v6sqmpbu3vvu>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <sqwajvt7utnt463tzxgwu2yctyn5m6bjwrslsnupfexeml6hkd@v6sqmpbu3vvu>
X-Debian-User: leitao
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@debian.org header.s=smtpauto.stravinsky header.b=DbG2fWv1;
       spf=none (google.com: leitao@debian.org does not designate permitted
 sender hosts) smtp.mailfrom=leitao@debian.org
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

On Tue, Nov 25, 2025 at 08:02:16AM -0800, Breno Leitao wrote:
> 6. Meanwhile, kfence's toggle_allocation_gate() on another CPU attempts to
> perform a synchronous operation across all CPUs, which correctly triggers a CSD
> lock timeout because CPU#0 is stuck in the busy loop with IRQs disabled.
 
I've hacked a patch to disable kfence IPIs during machine shutdown, and
with it loaded, I don't reproduce the problem described in this thread.

	Author: Breno Leitao <leitao@debian.org>
	Date:   Tue Nov 25 07:21:55 2025 -0800

	mm/kfence: add reboot notifier to disable KFENCE on shutdown
	
	Register a reboot notifier to disable KFENCE and cancel any pending
	timer work during system shutdown. This prevents potential IPI
	synchronization issues that can occur when KFENCE is active during
	the reboot process.
	
	The notifier runs with high priority (INT_MAX) to ensure KFENCE is
	disabled early in the shutdown sequence.
	
	Signed-off-by: Breno Leitao <leitao@debian.org>

	diff --git a/mm/kfence/core.c b/mm/kfence/core.c
	index 727c20c94ac5..5810afaaf6b4 100644
	--- a/mm/kfence/core.c
	+++ b/mm/kfence/core.c
	@@ -26,6 +26,7 @@
	#include <linux/panic_notifier.h>
	#include <linux/random.h>
	#include <linux/rcupdate.h>
	+#include <linux/reboot.h>
	#include <linux/sched/clock.h>
	#include <linux/seq_file.h>
	#include <linux/slab.h>
	@@ -819,6 +820,21 @@ static struct notifier_block kfence_check_canary_notifier = {
	
	static struct delayed_work kfence_timer;
	
	+static int kfence_reboot_callback(struct notifier_block *nb,
	+				  unsigned long action, void *data)
	+{
	+	/* Disable KFENCE to avoid IPI synchronization during shutdown */
	+	WRITE_ONCE(kfence_enabled, false);
	+	/* Cancel any pending timer work */
	+	cancel_delayed_work_sync(&kfence_timer);
	+	return NOTIFY_OK;
	+}
	+
	+static struct notifier_block kfence_reboot_notifier = {
	+	.notifier_call = kfence_reboot_callback,
	+	.priority = INT_MAX, /* Run early to stop timers ASAP */
	+};
	+
	#ifdef CONFIG_KFENCE_STATIC_KEYS
	/* Wait queue to wake up allocation-gate timer task. */
	static DECLARE_WAIT_QUEUE_HEAD(allocation_wait);
	@@ -901,6 +917,8 @@ static void kfence_init_enable(void)
		if (kfence_check_on_panic)
			atomic_notifier_chain_register(&panic_notifier_list, &kfence_check_canary_notifier);
	
	+	register_reboot_notifier(&kfence_reboot_notifier);
	+
		WRITE_ONCE(kfence_enabled, true);
		queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
 

Alexander, Marco and Kasan maintainers:

What is the potential impact of disabling KFENCE during reboot
procedures?

The primary motivation is to avoid triggering IPIs during the machine
teardown process, mainly when the nbconsole is not running in threaded
mode.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/k4awh5dgzdd3dp3wmyl3z3a7w6nhoo6pszgeflbnbtdyxz47yd%40ir5cgbvypdct.
