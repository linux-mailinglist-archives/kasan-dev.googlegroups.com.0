Return-Path: <kasan-dev+bncBDQ27FVWWUFRBLHG7LYAKGQE6UUMWZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id D662913B9C6
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 07:37:33 +0100 (CET)
Received: by mail-yb1-xb37.google.com with SMTP id c16sf4647698ybi.2
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2020 22:37:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579070252; cv=pass;
        d=google.com; s=arc-20160816;
        b=ib/se456t5UIOyWZ3YK1Eiil8UQ7CTwyu/JoZ1PrbNPGcqfDzCMYpiJN/JA5Pp8tQi
         tN8QPJ+UFoSq31f7b2mnKjBbdCmHg72FPF3Z9wR0ZrriTdIWmzB7D9EAJJUODRK1RRlh
         1EPewLsB+Pjr1dscR0ndeKJsfTKZ6w9tmzCKCVDmSklXD+XNs5johKGroG/eGhP97eBs
         5YPGYH6PLN+jtqLjdgZ3hzp3PBzT/1C5z27z5q/rQfEYTHKFLVRSI3+UJnt3SVRfveXe
         iV3ci4V59emqhW2ovZO6TG7/aGZdRRkT8o63NBHzyPaabUqfzrEh5a5yHhfI049onxKh
         raEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=E1C2pMT59DrnQyJng9ukD5VLWaFFuoHvvNDLiKSiiN4=;
        b=j3r6K36+fgyZKmka/VLb65VDYpa4duAKCPK/OfrETKcwD57mYDqVHzhB1ONLKJB4y4
         JQXJKuXsucczTWhggDC5hpUUfKmMcDn4bD4yn7IjrqDGUSujAM/etsxRCIsGkyctZVku
         +50dmIkm4PvDw4wrFAleFCzegGWwcaF+OGAa7Dp+gKvIAMBH67cE3O/e8l2GY10/aAXU
         KhZiecrFSc8JJ3PMfxuski8RUZoekI6LJV4gq74fBYxFXySD8JH6KpnIWai2GcYLK4pm
         7NIVRvtWeeVnPtzGkb3iSl9MN+fynbjXicOtMeiVRP8aGkbP9h1769g9v2OKRrWajFND
         VdUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Osp9npf9;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E1C2pMT59DrnQyJng9ukD5VLWaFFuoHvvNDLiKSiiN4=;
        b=D9Jbju0z6CcMY/U1Z5gr0SFyAGeeYvjWPbr1zwvp+9jy5QRzX+E4hjFfCqGw0bWWAT
         ubc73VHf3MiVg/e6mmJPpePBK33bm7+N3w2CzQumjFRZdXhGrIOfPFnZsRLz6iIzts+D
         Awm/4BAduq/Cp8ibw5nbMUfZr7xuG/8gkmofIjRqzjextE/LjN7kaVGwqWyj+vqhTZr/
         IsvPpvCPKGVxwsCmFQYpQNQ4scx1CiYvjRCcoYV55gRMM98G9biL2oNWiKXlPinqMmVq
         NfshRGXB7GSm+WzwNio93YysAcLmWbvhAxuWF9CX6waz//Xs8wfbz8GvJs+yWSiSQXOF
         ocSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=E1C2pMT59DrnQyJng9ukD5VLWaFFuoHvvNDLiKSiiN4=;
        b=pNwbq4a/fycgaPENwwI/TePVUprdDyF+GiRbFhs9He6y+yzqE+sfzHxNOQT4T9EiP2
         paSDmkISwM3+0qQ1v2o6FE2Pji4DH2uorPnCXWF+BrzCmNGNor0hwcc+N+Ys8IyRnmw1
         eVxfJb0HSBGbUtz9qQe6IrzKMPsMqtS5aSRpqm9eFneOzLQKkLTNAu3BGeoOB8hXKx6d
         uTQONVnRicetntImOffv44vZ7wBXr/HmSCZZT6Y4xXEl9ohOTcEQzDEefEqhVVOkbp+4
         5JNJAXmaJy/S8+0EjBYVvjxRu6+7YpgMrI1sbYyQr+tvuOpsFE/lmA7tiHl/fOeIQ/e7
         mNUA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXa2fbReydmqY+mCxyKTp3arpTCdcsqi5GvNJWbeofn7xj5b/d+
	i/BDJZ+RrDna2h6z8hEzXNM=
X-Google-Smtp-Source: APXvYqz5ypewZzuqOgyJ1cpM53BAJ9epU98cvdALMqzlV968bTnE3s3mdPMHKguXty6WBCxZ9ASgpw==
X-Received: by 2002:a5b:286:: with SMTP id x6mr19679807ybl.92.1579070252585;
        Tue, 14 Jan 2020 22:37:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:66c6:: with SMTP id a189ls2835681ywc.8.gmail; Tue, 14
 Jan 2020 22:37:32 -0800 (PST)
X-Received: by 2002:a81:1d81:: with SMTP id d123mr21505393ywd.195.1579070252202;
        Tue, 14 Jan 2020 22:37:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579070252; cv=none;
        d=google.com; s=arc-20160816;
        b=0q1sFlw2wMqzs/nSd2lxi6XfGggfoLNYah7h3o65oB1W/f9XTlbwV49//fyLdH4C2Q
         quC8wbYmW6U6aJ8B77pVC60D7GILaEEovx9TkElSjXOQekRg8C06IDh6A5uQJIqhReoN
         OCASWLCDNpGvDsFP2HBiTGgPPu17gCICfXxXNyX3Qtgtz1sHD6HTBD82fzwz9mjTnOqh
         t3gyrlq4mTt7HLOZvfO39SHWkb6+VXWZK46tw5htOtaBAsSAbssOzddQKJWYkoYvV0vj
         0trFhb9qhXW1ML6hPmmT5Tx+lVYCJWb/60YASV/peJUAopmwqZe+q0RhJPP5kZv5muU7
         iGMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=SZL5+wtQV8L4I+t/B21mqCEwpOPwMzNG/NjS3uxYK18=;
        b=Cbr5Pf4i3SBoreVIRxIrgSVQNhBDs/BvtOjUNqdO0KbXO30O9bmMweO10lHE8CEnvG
         21ADdoqmNtFA5kvfbJexdiGHKpwnPCMB4GQn4s4KaJ5jw5iXRNLvI5dol95VyA9ARog3
         mHzSW3nwAtoLZmjcAPmSVK7C2LT/fHFBJkW+q3jfRixKxcWl15Mcn5bYujV9wFznBFEU
         T1hqHXRCsmrJIijLGF3Pc+vffJfbq3/5qeBfZftB4bpU/0luKmLblusHU/DZPV5bmHiW
         frK+Oj992MQqUNWtwc+Uph2WXUHIYdOnOar+uW3abbO9ZY5KCtddkY03Tre5JUNAG547
         ZdDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Osp9npf9;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id n67si955335ywd.3.2020.01.14.22.37.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Jan 2020 22:37:32 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id q10so8026613pfs.6
        for <kasan-dev@googlegroups.com>; Tue, 14 Jan 2020 22:37:32 -0800 (PST)
X-Received: by 2002:a63:2949:: with SMTP id p70mr31822201pgp.191.1579070251356;
        Tue, 14 Jan 2020 22:37:31 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-8d73-bc9d-5592-cfd7.static.ipv6.internode.on.net. [2001:44b8:1113:6700:8d73:bc9d:5592:cfd7])
        by smtp.gmail.com with ESMTPSA id k12sm18720866pgm.65.2020.01.14.22.37.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 Jan 2020 22:37:30 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com
Cc: linuxppc-dev@lists.ozlabs.org,
	linux-arm-kernel@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-xtensa@linux-xtensa.org,
	x86@kernel.org,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH 0/2] Fix some incompatibilites between KASAN and FORTIFY_SOURCE
Date: Wed, 15 Jan 2020 17:37:08 +1100
Message-Id: <20200115063710.15796-1-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=Osp9npf9;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

3 KASAN self-tests fail on a kernel with both KASAN and FORTIFY_SOURCE:
memchr, memcmp and strlen. I have observed this on x86 and powerpc.

When FORTIFY_SOURCE is on, a number of functions are replaced with
fortified versions, which attempt to check the sizes of the
operands. However, these functions often directly invoke __builtin_foo()
once they have performed the fortify check.

This breaks things in 2 ways:

 - the three function calls are technically dead code, and can be
   eliminated. When __builtin_ versions are used, the compiler can detect
   this.

 - Using __builtins may bypass KASAN checks if the compiler decides to
   inline it's own implementation as sequence of instructions, rather than
   emit a function call that goes out to a KASAN-instrumented
   implementation.

The patches address each reason in turn.

As a result, we're also able to remove a snippet of code copy-pasted
between every KASAN implementation that tries (largely unsuccessfully) to
disable FORTIFY_SOURCE under KASAN.

Daniel Axtens (2):
  kasan: stop tests being eliminated as dead code with FORTIFY_SOURCE
  string.h: fix incompatibility between FORTIFY_SOURCE and KASAN

 arch/arm64/include/asm/string.h   |  4 ---
 arch/powerpc/include/asm/string.h |  4 ---
 arch/s390/include/asm/string.h    |  4 ---
 arch/x86/include/asm/string_64.h  |  4 ---
 arch/xtensa/include/asm/string.h  |  3 --
 include/linux/string.h            | 49 +++++++++++++++++++++++--------
 lib/test_kasan.c                  | 30 ++++++++++++-------
 7 files changed, 56 insertions(+), 42 deletions(-)

-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200115063710.15796-1-dja%40axtens.net.
