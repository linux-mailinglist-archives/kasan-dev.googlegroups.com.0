Return-Path: <kasan-dev+bncBAABBJNNZ6HQMGQEUEOHSDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id CA95149F874
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 12:42:31 +0100 (CET)
Received: by mail-pg1-x53e.google.com with SMTP id t1-20020a6564c1000000b002e7f31cf59fsf3249641pgv.14
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 03:42:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643370150; cv=pass;
        d=google.com; s=arc-20160816;
        b=HiGRfnQWD/n2/nPDZaMqCqCYW0hsNKnfwzUH+XpbeM6BJyzUWixAulayW1UT02Eb0l
         Lq3R7SM3xHD+V29XUnbsM/zKX62OGSWMbKFcUm5ee1qHa5Renp7mi1anew2pxyMIvOaD
         NEERzAfv+CSeJR8xcOKfWvM9IaRvo4xEYhZVnBnqNp3iwpqkq6oEbNlzN4EKucv1GGtM
         eCQgJaY7h/q8hM0E9YdXVRiRK/XiUndo0ZBJC5OfFkGQDQHaStGo51ZfU80VBaBnOrSH
         3SIpS9eFFtbsewXxCIY/MTpnMp1wv/jg+dR+WtWRlYmcdF7m4QqaKxCfx9Ut8RsPU7WL
         iTmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date:subject:cc:to:from
         :mime-version:sender:dkim-signature;
        bh=6YL5AXhKyL33dUsbMoyWIzAPf4dLXNgUizYqhmWoLws=;
        b=bKofYLfTUj39YWDWpihU2mVYfv3+8stzWZK8ZdSRtl3ASWT7GWYKzzqybRSRvFp9zO
         YcbcIS4VhZhSSPM32JvGKQDtBsELr4UdPhsuEE1uEb3zrumdGjG8OgVrvrXSMRvmJMPE
         AyCl09SX1dWo1pyYIsniNCmfGFt9PI1QWucEqVnlpPuPCdPh70L2WsErREESi32S5oPU
         Bk0ZtaUgZVgmHjXsTZA1x4YR9lWy5aCElGJQKCxekeY2eBfSQfAm9bNLjTCP2Xa4MhNT
         Vswr8lJNUN4DzKZHBfpwWxhmvL5RVNKBc+0ygkMc235ZcHzGV2/vuADGnnP9dU/sYI45
         rPTw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:to:cc:subject:date:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6YL5AXhKyL33dUsbMoyWIzAPf4dLXNgUizYqhmWoLws=;
        b=sZkx8+q/amq2lYibLmoCkjQcqVRO5GgDU7KZywRqmMUhSMHPrMTi5v6Tjmfa4GQQu0
         Hm3nGxHu1sLnuhkhZtL+XnCx30zlUSt9AwMWe8ku9rx0nBQb52Qi4MWZt3RskIKQDA4K
         41KM5Ec4LndMds/2TGL4/x6Y8Dw8/QvEeg1Z2m7VCtjH/R5C5zhCWmkTdaUGRfE1CYnf
         6lLU36S1ScqyX+Fak/gteYB27RI63dQB0+fbD1N6oSqsqn4we/IsPYQ6RjU4yQOeXT7R
         1duXt42Wh/Z29hwFTUxniiCBH6qmPv6wpCGxkcIhA1u7qJlEjiMM2E14nYmZ9+6mV62Z
         VaIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6YL5AXhKyL33dUsbMoyWIzAPf4dLXNgUizYqhmWoLws=;
        b=wdlYqXMCqpMlf9eDSUDI35pjzFS7c8SYDZ+hZXRfVsqzZ1xKTdlYUhsUtoUasMIGEA
         0SpBoTHGwQAPrKN5HHiTBiwBqKlJRCLyRJXPEylyLcC/2H7OrqyqJgnDGZzPrsQHJqkr
         yjVVu2E4u341ns7tpfkcKsFkDhEYrwO/wIIjPRqADamOlogqtvwJO8FWp33Z0YJCTl3B
         tAG14nZ/6dRywp4yolBBCjHEur2IcX6CrDk1EG4xp65+ACsC7aw+skNx+CJ/CjRSVVMa
         E/6k7CSTbSAVlo18N73Vz6XCU9HXsQu5IgiFu7Jcl9NLWo5MfpJ+fQF0mKRqHt4xaPYm
         W+eg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531w4kxaGqCOeAh9EQjqn05Pz7JUYh9zjo42daDyszQ8LRAK8zE7
	99Zo+LKsQrCGaYobphbmwx8=
X-Google-Smtp-Source: ABdhPJz8QQhlVtlFzpGXwgP5w/3HiTC/LwbPLzTZjkEwxAR75oeUqIppSH+0OJ4eq66zrkHNnKTmbw==
X-Received: by 2002:a05:6a00:158c:: with SMTP id u12mr7592830pfk.18.1643370149455;
        Fri, 28 Jan 2022 03:42:29 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d510:: with SMTP id b16ls5875682plg.10.gmail; Fri,
 28 Jan 2022 03:42:28 -0800 (PST)
X-Received: by 2002:a17:902:e782:: with SMTP id cp2mr7841352plb.162.1643370148769;
        Fri, 28 Jan 2022 03:42:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643370148; cv=none;
        d=google.com; s=arc-20160816;
        b=YjXZt79pM9B691mbAVFatTlDy453nFiF1Q88h/pNdBaDXhz+D7pLVeZ7GL13oVJso/
         vMy5y8bvW4otZi4mEsZCUiA9GnOqwdkvwz9FpyeP+j44/M3ZroI3KdRTRYNAwclKy3fI
         TkvBxkNHS9+cmqxTUQPqDOzHva1aAqjjyAvPt93l0KOBYz3DRQJ/2m5J3baSXNSBNBIx
         ZJGd/0lGUlthcu3PnmVbmYM7dWjOT4i9uUqk1OuTmMnDlr36cs0jA5WgEv5M/Syh/OA9
         iFU/fb4HWYK7FsmPRl3Yp0Ba8vE+1nxA0TEmQmmTZX6EUJhz2dgeD61A/3LGJPjFKhkt
         3mMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:subject:cc:to:from;
        bh=r/MD6SYJblVo8YdwrveTyVah6xhhYO72b54KHENy91g=;
        b=e5OSSB5FMcgEK8L30xRzqUungdzE8wFCUHCvizuH/oNKAlmAmAvWw11u9q99lzAWuU
         +xsreQm7hAzrbJISS+4G4czyJZSWNy4g2SpYiOp7nnf0P3rrgqoBRHSDMyXxu1v9JtCZ
         LH5SNnGKaguTYdaCXdr6WawmQIGT4LUVh/NS+DJ8Vsw738j6QfFIRQ9UOshs0NVHj1rw
         NaNe/DCmTjm7DowTuiF4AXcFSj1s6DfTmMjCUcppzmdmeOvWUsji1+rFaDJIRJRW/5yP
         tQt1S/oWlAdRPecwLHiNwBEByPD9mmM4TuMpvCOAI8aSowlhwIdSoenhB9qvCO/zIFHr
         5svw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id d14si286709plg.7.2022.01.28.03.42.28
        for <kasan-dev@googlegroups.com>;
        Fri, 28 Jan 2022 03:42:28 -0800 (PST)
Received-SPF: pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from linux.localdomain (unknown [113.200.148.30])
	by mail.loongson.cn (Coremail) with SMTP id AQAAf9Dxb+Kh1vNhREgFAA--.17556S2;
	Fri, 28 Jan 2022 19:42:26 +0800 (CST)
From: Tiezhu Yang <yangtiezhu@loongson.cn>
To: Baoquan He <bhe@redhat.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Andrew Morton <akpm@linux-foundation.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Marco Elver <elver@google.com>
Cc: kexec@lists.infradead.org,
	linux-doc@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH 0/5] Update doc and fix some issues about kdump
Date: Fri, 28 Jan 2022 19:42:20 +0800
Message-Id: <1643370145-26831-1-git-send-email-yangtiezhu@loongson.cn>
X-Mailer: git-send-email 2.1.0
X-CM-TRANSID: AQAAf9Dxb+Kh1vNhREgFAA--.17556S2
X-Coremail-Antispam: 1UD129KBjDUn29KB7ZKAUJUUUUU529EdanIXcx71UUUUU7v73
	VFW2AGmfu7bjvjm3AaLaJ3UjIYCTnIWjp_UUUY37k0a2IF6F4UM7kC6x804xWl14x267AK
	xVW8JVW5JwAFc2x0x2IEx4CE42xK8VAvwI8IcIk0rVWrJVCq3wAFIxvE14AKwVWUJVWUGw
	A2ocxC64kIII0Yj41l84x0c7CEw4AK67xGY2AK021l84ACjcxK6xIIjxv20xvE14v26r1I
	6r4UM28EF7xvwVC0I7IYx2IY6xkF7I0E14v26r4j6F4UM28EF7xvwVC2z280aVAFwI0_Gc
	CE3s1l84ACjcxK6I8E87Iv6xkF7I0E14v26rxl6s0DM2AIxVAIcxkEcVAq07x20xvEncxI
	r21l5I8CrVACY4xI64kE6c02F40Ex7xfMcIj6xIIjxv20xvE14v26r1j6r18McIj6I8E87
	Iv67AKxVW8JVWxJwAm72CE4IkC6x0Yz7v_Jr0_Gr1lF7xvr2IYc2Ij64vIr41lFIxGxcIE
	c7CjxVA2Y2ka0xkIwI1lc2xSY4AK67AK6r4kMxAIw28IcxkI7VAKI48JMxC20s026xCaFV
	Cjc4AY6r1j6r4UMI8I3I0E5I8CrVAFwI0_Jr0_Jr4lx2IqxVCjr7xvwVAFwI0_JrI_JrWl
	x4CE17CEb7AF67AKxVWUtVW8ZwCIc40Y0x0EwIxGrwCI42IY6xIIjxv20xvE14v26r1j6r
	1xMIIF0xvE2Ix0cI8IcVCY1x0267AKxVWUJVW8JwCI42IY6xAIw20EY4v20xvaj40_WFyU
	JVCq3wCI42IY6I8E87Iv67AKxVWUJVW8JwCI42IY6I8E87Iv6xkF7I0E14v26r4j6r4UJb
	IYCTnIWIevJa73UjIFyTuYvjxU4g18DUUUU
X-CM-SenderInfo: p1dqw3xlh2x3gn0dqz5rrqw2lrqou0/
X-Original-Sender: yangtiezhu@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
Content-Type: text/plain; charset="UTF-8"
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

Tiezhu Yang (5):
  docs: kdump: update description about sysfs file system support
  docs: kdump: add scp sample to write out the dump file
  kcsan: unset panic_on_warn before calling panic()
  sched: unset panic_on_warn before calling panic()
  kfence: unset panic_on_warn before calling panic()

 Documentation/admin-guide/kdump/kdump.rst | 10 +++++++---
 kernel/kcsan/report.c                     | 10 +++++++++-
 kernel/sched/core.c                       | 11 ++++++++++-
 mm/kfence/report.c                        | 10 +++++++++-
 4 files changed, 35 insertions(+), 6 deletions(-)

-- 
2.1.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1643370145-26831-1-git-send-email-yangtiezhu%40loongson.cn.
