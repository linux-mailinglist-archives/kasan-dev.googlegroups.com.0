Return-Path: <kasan-dev+bncBDY3NC743AGBBOVG3D2AKGQEEUXNXJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3e.google.com (mail-vs1-xe3e.google.com [IPv6:2607:f8b0:4864:20::e3e])
	by mail.lfdr.de (Postfix) with ESMTPS id D9DE61A8B5C
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Apr 2020 21:47:07 +0200 (CEST)
Received: by mail-vs1-xe3e.google.com with SMTP id j19sf596508vsm.11
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Apr 2020 12:47:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586893627; cv=pass;
        d=google.com; s=arc-20160816;
        b=TVXvy1ak72tQ3CohmL/uBhEEFDCG2i2mLt6eSh/A+hQzL0nrMYS2peqUgoKtdBj4Qx
         jNj61rll05iAfhA337CQaCBRgRdP0BOFMjza/VAc/MIR7y6bY1fNE5/IxBV4rDmE/Gp7
         rc/FCTYyInPXlsbUC1G+AFqmnPzBe2u0dbYh1i7NnFPOpxYjuFE8wkueub2m53US7VV8
         pG0d4h07Itc3HF/4ILEkdteHJaGU591O0PYp7GFfJ1TJaZAuoiRzm6507P4qLgCA5oX4
         Upszvl3gXxr0jFOj/tjg6NmHSqb7DTpiRr657FHTo2KtwaIbk02iIFLxWrKcJqLvk/s/
         XiOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=epaFkr7/4D82JXPBEToiA8/RMj4gLENxZF2d0nJgcq8=;
        b=iHukt1Iq8AIP+0Tu4/Bbz/C76It/p6rM+B2UJrFwbAco8vszSImwKD1ZFtXBriltPx
         uBz7qGlJhaWnFj3lhQcWvqMeIUQUp1dur85lTVNN96YM6Jg9ffe27PyFDodEle0Lyd7z
         bI9ZRKFIHhRxh//9aucWFz+0hJnNrO1GCC5E2Y/C89xhAvJihv/AmI3bMvTDPaPruGDg
         0ab29oxvAE/wHvAu7+jqeD3aeirZn1w4f2+77oEET7+jnEGxgqG3k6VDoV1uI1/jnodM
         EyMgwQlGg6UlQZXPivuuebDFGwf82sWBFuE+QXXMG8gcynLbl9N4mFPdrIXhOs0num2X
         5nww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 216.40.44.106 is neither permitted nor denied by best guess record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=epaFkr7/4D82JXPBEToiA8/RMj4gLENxZF2d0nJgcq8=;
        b=Ds2gXIBDi0AnvpG4qWwWdgoNNoRptM7KMOS5Suq+CNe8swG/9C/zocvC9evBFZX5c2
         s7D9+jegYOz1YFijDHYfdDOSu7nclv0Ld3eCcMfGnu5VY1KCj57r0ZR1+h9faLP6xtqX
         UWJ+6GD4AtUAF+ou/MdB8HcrKdFZuWfgaLHZMnl7BdkMm31I2EyQ+uPmNF+UgdVct4c5
         ZHx6ZHGq2DDbevegqHhT4dWm+MlpxQpskfIlxn0vR0tjp1/xiZQg6L9oCdbSnqB1PNTi
         ThmTJpeHE4+QGYvmaoIiMYMFoDuKfX8k6qNrhu7OF+PZIutDjWryHFBI37J1atMI0mOR
         YfEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=epaFkr7/4D82JXPBEToiA8/RMj4gLENxZF2d0nJgcq8=;
        b=G8VnNgOCzK3Pr/44RySqJzLUaoJ1kCmEuaPJP6ShrAa/WTb0IScLD8qijf0829hUw+
         0UFJZ9LcLSURHF570P74SYwxFoMHsBnDjGf5NfzfxIYJNwniKfy8VM5f3TSdClPAPVLM
         PUF3JBLr5bDk6whaZppiIpeJZkBUcNMB202xRm+MF6M21yMANHoUVORvhht5xXukSNXA
         gm2SXjSrbDSn9Oai8ualn3UllTi+VbEZt2higIppMsE54oxgnZlBqFYNDuaPlhQ5j41x
         2StXzD45a3FTwECMGFmJmwhSOx9DhJ7W33kuEHh1GnHNl0BsNgDZ8qO6sa+mQ1OM601j
         vFrA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuaOcT87ZIrmUValeF9H/l5MD5Ib/CnU2RedPaG/WpO/fxbqYkvF
	0sAiT1VYrwm/MrZztlBfOKc=
X-Google-Smtp-Source: APiQypLYpj7THmHKCoE0J7G6xFewbPp5b1ThF2p2L4hVThFZnoPf6zpUs+XLzLLLaNgj8gTUa3Ix5Q==
X-Received: by 2002:a9f:21eb:: with SMTP id 98mr1721640uac.62.1586893626933;
        Tue, 14 Apr 2020 12:47:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:b0:: with SMTP id 45ls439499uaj.11.gmail; Tue, 14 Apr
 2020 12:47:06 -0700 (PDT)
X-Received: by 2002:ab0:30c9:: with SMTP id c9mr1807271uam.38.1586893626519;
        Tue, 14 Apr 2020 12:47:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586893626; cv=none;
        d=google.com; s=arc-20160816;
        b=aYtzNAT8P44R68ecZn8L6OzGS1jF0ob1apjf74lAkqSQnmKmrwY/oqlYa9KMMAghk8
         8T9X/a2uvDV7mNxWZqF4DKqAtZ25Ug9rFQAUIKzuZiVY0Xq/A853P2z9pjNkvu5WZizM
         VIXU5hv7Wf22FeEiiqxzmQtwvUzbfEndAMfQ3cefDXZeCETVflE2NiAKTJ1v5v/5F92E
         mY/LX908Y9oZxtd0dW6yR9uv7fm6Mz0RbC0N4T7Wg1pmkn+RnsAaaJBGvA5uwEW7dzS4
         H08HkNdc0X/ZAaabRyu94BNxN16YFTj4WU7cJIaReeKb5Eb/ksj3vmaSy5qvDxHPalV3
         IxbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id;
        bh=VnscjgQORv8+DUxED4aAg3y+BnsShE3ZTVnvVCvV31w=;
        b=NYiQMGjDSQY0II7YyA8tEO6v95y7/OTY2czscjJhWXymnoiUnOpD24SZB5b9aacB7v
         IdAsgtCIxs6ZZEg4ZGM5RjKCBlJ4/Xuci4K9ETYxSATpwdePdmKF887rZeNIjwpyw3R5
         vk6iBEnpnd5wNWECK3DI+yVRq4+gzhegmgZOmBsdo2F/2DDF4yXGaDjaE97liyNhmGTg
         nE6USvSA3qMmAM3ysoYF5kL9BoLqAatFG+ayNGVLPAPBjk2U1kfMoUMVjtMR1bAHPiOx
         RfoBaHQmqRkPJnBWNLD/1EMmnPS1Sjdp9QJBqa5k1a8w9MjFu3uUdjWMf5A5mmQviyLF
         Nrxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 216.40.44.106 is neither permitted nor denied by best guess record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
Received: from smtprelay.hostedemail.com (smtprelay0106.hostedemail.com. [216.40.44.106])
        by gmr-mx.google.com with ESMTPS id k19si113444uaa.0.2020.04.14.12.47.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 Apr 2020 12:47:06 -0700 (PDT)
Received-SPF: neutral (google.com: 216.40.44.106 is neither permitted nor denied by best guess record for domain of joe@perches.com) client-ip=216.40.44.106;
Received: from filter.hostedemail.com (clb03-v110.bra.tucows.net [216.40.38.60])
	by smtprelay06.hostedemail.com (Postfix) with ESMTP id 9E3611802B57F;
	Tue, 14 Apr 2020 19:47:05 +0000 (UTC)
X-Session-Marker: 6A6F6540706572636865732E636F6D
X-Spam-Summary: 2,0,0,,d41d8cd98f00b204,joe@perches.com,,RULES_HIT:41:355:379:599:966:988:989:1260:1277:1311:1313:1314:1345:1359:1437:1515:1516:1518:1534:1537:1561:1593:1594:1711:1714:1730:1747:1777:1792:2196:2199:2393:2559:2562:2828:3138:3139:3140:3141:3142:3622:3865:3867:3872:3874:4321:4385:5007:6742:6743:10004:10400:10848:11232:11658:11914:12297:12740:12760:12895:13069:13311:13357:13439:14659:14721:21080:21627:30045:30054:30070:30091,0,RBL:none,CacheIP:none,Bayesian:0.5,0.5,0.5,Netcheck:none,DomainCache:0,MSF:not bulk,SPF:,MSBL:0,DNSBL:none,Custom_rules:0:0:0,LFtime:1,LUA_SUMMARY:none
X-HE-Tag: coal59_5a1e7cc02a463
X-Filterd-Recvd-Size: 2796
Received: from XPS-9350.home (unknown [47.151.136.130])
	(Authenticated sender: joe@perches.com)
	by omf07.hostedemail.com (Postfix) with ESMTPA;
	Tue, 14 Apr 2020 19:46:59 +0000 (UTC)
Message-ID: <2a58f592879cf67b4c6b8e859ce87e1f9652902a.camel@perches.com>
Subject: Re: [PATCH v2 2/2] crypto: Remove unnecessary memzero_explicit()
From: Joe Perches <joe@perches.com>
To: Waiman Long <longman@redhat.com>, Michal =?ISO-8859-1?Q?Such=E1nek?=
	 <msuchanek@suse.de>
Cc: Christophe Leroy <christophe.leroy@c-s.fr>, Andrew Morton
 <akpm@linux-foundation.org>, David Howells <dhowells@redhat.com>, Jarkko
 Sakkinen <jarkko.sakkinen@linux.intel.com>, James Morris
 <jmorris@namei.org>, "Serge E. Hallyn" <serge@hallyn.com>, Linus Torvalds
 <torvalds@linux-foundation.org>, Matthew Wilcox <willy@infradead.org>,
 David Rientjes <rientjes@google.com>, linux-mm@kvack.org, 
 keyrings@vger.kernel.org, linux-kernel@vger.kernel.org, x86@kernel.org, 
 linux-crypto@vger.kernel.org, linux-s390@vger.kernel.org, 
 linux-pm@vger.kernel.org, linux-stm32@st-md-mailman.stormreply.com, 
 linux-arm-kernel@lists.infradead.org, linux-amlogic@lists.infradead.org, 
 linux-mediatek@lists.infradead.org, linuxppc-dev@lists.ozlabs.org, 
 virtualization@lists.linux-foundation.org, netdev@vger.kernel.org, 
 intel-wired-lan@lists.osuosl.org, linux-ppp@vger.kernel.org, 
 wireguard@lists.zx2c4.com, linux-wireless@vger.kernel.org, 
 devel@driverdev.osuosl.org, linux-scsi@vger.kernel.org, 
 target-devel@vger.kernel.org, linux-btrfs@vger.kernel.org, 
 linux-cifs@vger.kernel.org, samba-technical@lists.samba.org, 
 linux-fscrypt@vger.kernel.org, ecryptfs@vger.kernel.org, 
 kasan-dev@googlegroups.com, linux-bluetooth@vger.kernel.org, 
 linux-wpan@vger.kernel.org, linux-sctp@vger.kernel.org, 
 linux-nfs@vger.kernel.org, tipc-discussion@lists.sourceforge.net, 
 cocci@systeme.lip6.fr, linux-security-module@vger.kernel.org, 
 linux-integrity@vger.kernel.org
Date: Tue, 14 Apr 2020 12:44:49 -0700
In-Reply-To: <578fe9b6-1ccd-2698-60aa-96c3f2dd2c31@redhat.com>
References: <20200413211550.8307-1-longman@redhat.com>
	 <20200413222846.24240-1-longman@redhat.com>
	 <eca85e0b-0af3-c43a-31e4-bd5c3f519798@c-s.fr>
	 <e194a51f-a5e5-a557-c008-b08cac558572@redhat.com>
	 <20200414191601.GZ25468@kitsune.suse.cz>
	 <578fe9b6-1ccd-2698-60aa-96c3f2dd2c31@redhat.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.34.1-2
MIME-Version: 1.0
X-Original-Sender: joe@perches.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 216.40.44.106 is neither permitted nor denied by best guess
 record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
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

On Tue, 2020-04-14 at 15:37 -0400, Waiman Long wrote:
> OK, I can change it to clear the key length when the allocation failed
> which isn't likely.


Perhaps:

	kfree_sensitive(op->key);
	op->key = NULL;
	op->keylen = 0;

but I don't know that it impacts any possible state.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2a58f592879cf67b4c6b8e859ce87e1f9652902a.camel%40perches.com.
