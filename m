Return-Path: <kasan-dev+bncBDEKVJM7XAHRBCNN6TUAKGQEDZ2R2GY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 444C95EDF7
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jul 2019 22:56:42 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id s18sf1553728wru.16
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jul 2019 13:56:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562187402; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ch7WVbydsQHSreZbIVebvDbEplYcd595JZ8/PtRabuShrxhU2MxKfRfpVxJPyE27/i
         33F1+KbdyZjJ6brS6rSDv0Fijenj2byuPRxMX3mraEUS6Xu47OmVuM58amYaUfFQ+5OL
         3kP2fgz+ZZ7DHI7fl1lZLJDTUWvDl6gIeZifvwzLXMA89B/iBGUYMLI9LzMmwfArJMQo
         t1LkoYv8gJ9LEPAzESwIhmXYkIhxHTyEYciOJTFCQHIvU9NckHXTqaS4d/yqEoQ/eqxf
         tbS9fpaDUcY/oP+dcMMgsRfw8OfdmLWQn27f18mk6E1uH46JiieoViK3aaQPlD1Fn6Az
         +/eA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=iZbsl6inq7jA8QRMAcE/6T33hwCEOpe5SsYg3UnjVNs=;
        b=TCWCA3HayYq/5bnxDLtlwMyHPOEMNxm/7tJZ1waCRfxy92QiFR+cJKmgiVjgrTCzlV
         /ell5nFGx9Ujo7c8JuZ7HPO/ck+VoWUjTOgtsDyWlYpv8LJp83+CBQutxKrJpuheTQWR
         6ccGHhiGOITKcOr+wbIstYA8tPzle2EFzoCj5o06LTqHvkINFgbqS2Ys6SIar1HPqfbe
         JpFWhFd8m2wn/Qy1s2+RdRwOZNrX0WORsPww+Heu+UOyc5YKJV9uOJ43zZgRJe9pVBGy
         adrRKdrS369BG3SmYG4KwKynGW9SWYmF6RgJjzsaW5tva42GFUk0gRI38m4diDM58wCT
         hQig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.187 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iZbsl6inq7jA8QRMAcE/6T33hwCEOpe5SsYg3UnjVNs=;
        b=oengRsCM25auLtuWqjubtYygzaKppcnfeM1fdWT2b9QqP3qBlKJ26t9FFUuyHo5sNf
         Zo9VeYvVrUt146R2X1WeM5ZeErlKqmyoR4MJFzGcXobNNAEWL///QevZ6lHpRNydEkDO
         xiuRexOmgcQSvtSI8nZdq0/2SCFpD1/EUzhmM2tI06lQGLMMIB+iwXB75e8eDM+w02HF
         l3ufMS2WGqWEN5fHcBFSwRn90wjc0O+RZchPi7meILM1qHSn3tVWMAXNyacaYiMSeNMF
         o5zK/EMTDaCjfEQs9cxBDTH936sDaUVa7+Ax9uQULF0xVBFOXVW/0fLdShhpVpTCDHvm
         +GgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iZbsl6inq7jA8QRMAcE/6T33hwCEOpe5SsYg3UnjVNs=;
        b=MrTJ/rTJZCPmpjc8iB6bj4jw/WKGmt6NH9VEoKCw6BHwQYJreomd+bgNW1T06Nmn0y
         +tENm/57ANJ7OYSb5A+qrTubiGhiUv44p+mjDTD3FBziPLzBq91WY4CYY+0wfSGeUUVh
         +sYTqaozZnaxy8cp6ZAagi2GgljTZ+c/dORZvsnG2cMeSk3w0oJgCPmG42v8Ywd5VqIb
         ipw9iqYblZRIwJXNLFQsWMjERoU72NhqR/8H16mrszkfAydI6css5Hl1G05faPCjB9Lv
         mjgGBD45fjc6QFvLsATR39cojQwExRZg1xiXBtmcTcE9RZA/Jr+znquqeHe3ecMbJ/Hq
         hGqw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXA7ZIg88vj0vjgogj1EV71Pv+OjqebuwA4BMNFSIQnh9TGTAZt
	B8o0Pd/YagR5oaxgOQeFx8I=
X-Google-Smtp-Source: APXvYqxMCbnV8xhqaaQX12LaKpg3AiwlBjPoxWzTUWXLg2KrbNjAnKGzWWS6fjrmfZzakv7Zk1AMMA==
X-Received: by 2002:a5d:670b:: with SMTP id o11mr20685969wru.311.1562187402044;
        Wed, 03 Jul 2019 13:56:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fb4f:: with SMTP id c15ls807692wrs.11.gmail; Wed, 03 Jul
 2019 13:56:41 -0700 (PDT)
X-Received: by 2002:adf:f904:: with SMTP id b4mr3974343wrr.291.1562187401240;
        Wed, 03 Jul 2019 13:56:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562187401; cv=none;
        d=google.com; s=arc-20160816;
        b=zF6Q90/xeAuOZc2qMCe4K3eeR/Uw02MGPYGh7VBQdFErqQD6RjTFf9xtwIzRyLJZHx
         v59J7TmzSVnarr4quNEBDybu6I4CmGCin34ZwovdCNsygiw33fABr2nRlUjawitWcRDH
         2SIqvw13PGT7WHN0hu/bxbP7rzi/q7jWA8JODpaASdiyMwV4a0VWIf0tf0wL+jPkEEIy
         DsFgbVKscE2Cg2TQx3n2leVEiRYe4oc011rud1Qg8KKd4nNt/C/9XffoJORK6BDItlfv
         H7ATDJA3n0UuOSnNLDWQ2A/AxbNgxeVTBVLQKvEMQWOOEWFuuZHtq78vvnhMGf9zq4+G
         uQOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=JedBINZKkb5BYE6srGTfrrpmyMp18YxFHWY1mJ8AZxM=;
        b=sVE2VW96iKCBH0paUHYM/sbe1XZsHvg7DmsiIXMSbfU2HL4QB830EON6l3oEdgv8z+
         uS+pPxht4paz5lX8drtMPXULo6VD4fwlGRT8BK/5jB0DHQt7pApKG1h/Z7ljyEuHVADS
         r/B3zIdYzVgWTvoBhD9B89wpLLw87tqPuVhLKxiXsmnebO+81vzip3Ga/OUcAh3QZRlN
         /bL4GJw8poruHVnpwPeYDPBIzgaHcuI0qGUvcbKo5sG8pK3QE5jUzfku6VmlA4fFNiyN
         qKC99svXzyeX9UsOdXPw/k9De7J6t9q+eQrlYUUPWczZg4xBDDPO5wDAcYodfhIWCzRg
         zFZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.187 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
Received: from mout.kundenserver.de (mout.kundenserver.de. [212.227.126.187])
        by gmr-mx.google.com with ESMTPS id p23si167268wma.1.2019.07.03.13.56.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Jul 2019 13:56:41 -0700 (PDT)
Received-SPF: neutral (google.com: 212.227.126.187 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) client-ip=212.227.126.187;
Received: from threadripper.lan ([149.172.19.189]) by mrelayeu.kundenserver.de
 (mreue010 [212.227.15.129]) with ESMTPA (Nemesis) id
 1MCbZL-1hrszW1Wi3-009fcz; Wed, 03 Jul 2019 22:56:37 +0200
From: Arnd Bergmann <arnd@arndb.de>
To: Florian Fainelli <f.fainelli@gmail.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Abbott Liu <liuwenliang@huawei.com>,
	linux-arm-kernel@lists.infradead.org,
	kasan-dev@googlegroups.com,
	Linus Walleij <linus.walleij@linaro.org>,
	Arnd Bergmann <arnd@arndb.de>,
	Andrew Morton <akpm@linux-foundation.org>,
	Masahiro Yamada <yamada.masahiro@socionext.com>,
	Kees Cook <keescook@chromium.org>,
	linux-kernel@vger.kernel.org
Subject: [PATCH 3/3] kasan: increase 32-bit stack frame warning limit
Date: Wed,  3 Jul 2019 22:54:38 +0200
Message-Id: <20190703205527.955320-3-arnd@arndb.de>
X-Mailer: git-send-email 2.20.0
In-Reply-To: <20190703205527.955320-1-arnd@arndb.de>
References: <20190703205527.955320-1-arnd@arndb.de>
MIME-Version: 1.0
X-Provags-ID: V03:K1:8pSJiH+6Agod8nzM29uheH50kgOrBaKHZzl6ndhrvPiQDTdiHui
 W5pteQ/meterbUyb16uPXBdh/bTTq2+X7Dk5d7PAcip6R5BCBPu9tNJQGkCbISINyzxc4E3
 ufLi+uJnI/JUTqJcROzbiTnzXM5lLSFjTSMLV+q7duZFqGKVqJd+NvheDVswutkffm0UA2T
 TfDWqX7IhnITKKyiWsxrA==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:3Ix8Jf1u9lw=:pjqfTjTFLOmjIDonH9fhGO
 mHR6MCXiiA+Fcqph4cAytscXm6iAv/rKcr/9/TiHbHVVsjckLsemrX4ckG9DSoruNNgcyJZU6
 iOh8oppdJ0CmQLWMXd9XwgOkCOhnP9vSEcCbJv0xxPSh5jCSx9DuUzhZyzfxwQUQSPTD8ZZ2i
 t8FXl40rX/HMeA4I13WzDKH/5A2FNnIENm7M9rUTO700Bd7uTcBKAa7mlM+VdnwpaYWJ2RRtA
 WfqrTrQsGfObU4oOpKitmyB50dNiiNQMY56Dn6Dsh76mVyRlLUnc6QHQ4N0elrylTNwYj/ihI
 61Ox5FaGZmJDnXmnGoFY2sD2hny0rzusVuk5DpRThYWLJ5aatwd+B3ce7oeeO9NJRExGDIni4
 BHuWsm+m/eCraU0WPVTSM87vm1asD/ayohcM1+LdMTcoMzb9LlWx0ALq9MJu/CKgV9De8/3b9
 d3/VN94DYA9jeePRDe7XPFDTNj2Tn+7KpCruJu15FS9qth6rpir7mcXY3UcNbIiiAW0gMe7w+
 /OOpsa7lPMhg8f39gUMxhnjD6EufdR5k/B56MNvwwXPkkoRSgsJHf6gc9m7CmmxVLAsNOqOJm
 hN2h21mCFCGBXsyB5O/KCiZHxoEKeC65vGSjC034oyin5/vtkSzw+IjuYpdEELk2rIyJOnRgX
 zFxLbriBO8AJIvgkUiCOqFp7zMO5cjWvACRnImwP8b5VHSmDtbyQA6vmdcyt/fVyBlbr/1b48
 GyzK0D05aGULm/4LZ3MsFTAW2SkdaJZmX220Qg==
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 212.227.126.187 is neither permitted nor denied by best guess
 record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
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

Enabling kasan on 32-bit ARM introduces some new warnings in the
allmodconfig build due to mildly increased kernel stack usage, even when
asan-stack is disabled:

fs/select.c:621:5: error: stack frame size of 1032 bytes in function 'core_sys_select'
net/mac80211/mlme.c:4047:6: error: stack frame size of 1032 bytes in function 'ieee80211_sta_rx_queued_mgmt'
drivers/infiniband/sw/rxe/rxe_req.c:583:5: error: stack frame size of 1152 bytes in function 'rxe_requester'
fs/ubifs/replay.c:1193:5: error: stack frame size of 1152 bytes in function 'ubifs_replay_journal'
drivers/mtd/chips/cfi_cmdset_0001.c:1868:12: error: stack frame size of 1104 bytes in function 'cfi_intelext_writev'
drivers/ntb/hw/idt/ntb_hw_idt.c:1041:27: error: stack frame size of 1032 bytes in function 'idt_scan_mws'
drivers/mtd/nftlcore.c:674:12: error: stack frame size of 1120 bytes in function 'nftl_writeblock'
drivers/net/wireless/cisco/airo.c:3793:12: error: stack frame size of 1040 bytes in function 'setup_card'
drivers/staging/fbtft/fbtft-core.c:989:5: error: stack frame size of 1232 bytes in function 'fbtft_init_display'
drivers/staging/fbtft/fbtft-core.c:907:12: error: stack frame size of 1072 bytes in function 'fbtft_init_display_dt'
drivers/staging/wlan-ng/cfg80211.c:272:12: error: stack frame size of 1040 bytes in function 'prism2_scan'

Some of these are intentionally high, others are from sloppy coding
practice and should perhaps be reduced a lot.

For 64-bit, the limit is currently much higher at 2048 bytes, which
does not cause many warnings and could even be reduced. Changing the
limit to 1280 bytes with KASAN also takes care of all cases I see.
If we go beyond that with KASAN, or over the normal 1024 byte limit
without it, that is however something we should definitely address
in the code.

Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 lib/Kconfig.debug | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index 6d2799190fba..41b0ae9d05d9 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -251,7 +251,7 @@ config FRAME_WARN
 	int "Warn for stack frames larger than (needs gcc 4.4)"
 	range 0 8192
 	default 2048 if GCC_PLUGIN_LATENT_ENTROPY
-	default 1280 if (!64BIT && PARISC)
+	default 1280 if (!64BIT && (PARISC || KASAN))
 	default 1024 if (!64BIT && !PARISC)
 	default 2048 if 64BIT
 	help
-- 
2.20.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190703205527.955320-3-arnd%40arndb.de.
For more options, visit https://groups.google.com/d/optout.
